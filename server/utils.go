package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	capellaApi "github.com/attestantio/go-eth2-client/api/v1/capella"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost/config"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/sirupsen/logrus"
)

const (
	HeaderKeySlotUID     = "X-MEVBoost-SlotID"
	HeaderKeyVersion     = "X-MEVBoost-Version"
	HeaderKeyForkVersion = "X-MEVBoost-ForkVersion"
)

var (
	errHTTPErrorResponse  = errors.New("HTTP error response")
	errInvalidForkVersion = errors.New("invalid fork version")
	errInvalidTransaction = errors.New("invalid transaction")
	errMaxRetriesExceeded = errors.New("max retries exceeded")
)

// UserAgent is a custom string type to avoid confusing url + userAgent parameters in SendHTTPRequest
type UserAgent string

// BlockHashHex is a hex-string representation of a block hash
type BlockHashHex string

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set headers
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Set user agent header
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, userAgent)))

	// Set other headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// SendHTTPRequestWithRetries - prepare and send HTTP request, retrying the request if within the client timeout
func SendHTTPRequestWithRetries(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, headers map[string]string, payload, dst any, maxRetries int, log *logrus.Entry) (code int, err error) {
	var requestCtx context.Context
	var cancel context.CancelFunc
	if client.Timeout > 0 {
		// Create a context with a timeout as configured in the http client
		requestCtx, cancel = context.WithTimeout(context.Background(), client.Timeout)
	} else {
		requestCtx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	attempts := 0
	for {
		attempts++
		if requestCtx.Err() != nil {
			return 0, fmt.Errorf("request context error after %d attempts: %w", attempts, requestCtx.Err())
		}
		if attempts > maxRetries {
			return 0, errMaxRetriesExceeded
		}

		code, err = SendHTTPRequest(ctx, client, method, url, userAgent, headers, payload, dst)
		if err != nil {
			log.WithError(err).Warn("error making request to relay, retrying")
			time.Sleep(100 * time.Millisecond) // note: this timeout is only applied between retries, it does not delay the initial request!
			continue
		}
		return code, nil
	}
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType boostTypes.DomainType, forkVersionHex, genesisValidatorsRootHex string) (domain boostTypes.Domain, err error) {
	genesisValidatorsRoot := boostTypes.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) != 4 {
		return domain, errInvalidForkVersion
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return boostTypes.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into a struct
func DecodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

// GetURI returns the full request URI with scheme, host, path and args.
func GetURI(url *url.URL, path string) string {
	u2 := *url
	u2.User = nil
	u2.Path = path
	return u2.String()
}

// bidResp are entries in the bids cache
type bidResp struct {
	t         time.Time
	response  GetHeaderResponse
	blockHash string
	relays    []RelayEntry
}

// bidRespKey is used as key for the bids cache
type bidRespKey struct {
	slot      uint64
	blockHash string
}

func httpClientDisallowRedirects(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func weiBigIntToEthBigFloat(wei *big.Int) (ethValue *big.Float) {
	// wei / 10^18
	fbalance := new(big.Float)
	fbalance.SetString(wei.String())
	ethValue = new(big.Float).Quo(fbalance, big.NewFloat(1e18))
	return
}

func ComputeBlockHash(payload *capella.ExecutionPayload) (phase0.Hash32, error) {
	header, err := executionPayloadToBlockHeader(payload)
	if err != nil {
		return phase0.Hash32{}, err
	}
	return phase0.Hash32(header.Hash()), nil
}

func executionPayloadToBlockHeader(payload *capella.ExecutionPayload) (*types.Header, error) {
	transactionData := make([]*types.Transaction, len(payload.Transactions))
	for i, encTx := range payload.Transactions {
		var tx types.Transaction

		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, errInvalidTransaction
		}
		transactionData[i] = &tx
	}

	withdrawalData := make([]*types.Withdrawal, len(payload.Withdrawals))
	for i, w := range payload.Withdrawals {
		withdrawalData[i] = &types.Withdrawal{
			Index:     uint64(w.Index),
			Validator: uint64(w.ValidatorIndex),
			Address:   common.Address(w.Address),
			Amount:    uint64(w.Amount),
		}
	}
	withdrawalsHash := types.DeriveSha(types.Withdrawals(withdrawalData), trie.NewStackTrie(nil))

	// base fee per gas is stored little-endian but we need it
	// big-endian for big.Int.
	var baseFeePerGasBytes [32]byte
	for i := 0; i < 32; i++ {
		baseFeePerGasBytes[i] = payload.BaseFeePerGas[32-1-i]
	}
	baseFeePerGas := new(big.Int).SetBytes(baseFeePerGasBytes[:])

	return &types.Header{
		ParentHash:      common.Hash(payload.ParentHash),
		UncleHash:       types.EmptyUncleHash,
		Coinbase:        common.Address(payload.FeeRecipient),
		Root:            common.Hash(payload.StateRoot),
		TxHash:          types.DeriveSha(types.Transactions(transactionData), trie.NewStackTrie(nil)),
		ReceiptHash:     common.Hash(payload.ReceiptsRoot),
		Bloom:           types.Bloom(payload.LogsBloom),
		Difficulty:      common.Big0,
		Number:          new(big.Int).SetUint64(payload.BlockNumber),
		GasLimit:        payload.GasLimit,
		GasUsed:         payload.GasUsed,
		Time:            payload.Timestamp,
		Extra:           payload.ExtraData,
		MixDigest:       common.Hash(payload.PrevRandao),
		BaseFee:         baseFeePerGas,
		WithdrawalsHash: &withdrawalsHash,
	}, nil
}

// =========================== FIBER-BOOST UTILS ===================================== //

func convertBeaconBlockHeader(header *boostTypes.BeaconBlockHeader) *phase0.BeaconBlockHeader {
	return &phase0.BeaconBlockHeader{
		Slot:          phase0.Slot(header.Slot),
		ProposerIndex: phase0.ValidatorIndex(header.ProposerIndex),
		ParentRoot:    phase0.Root(header.ParentRoot),
		StateRoot:     phase0.Root(header.StateRoot),
		BodyRoot:      phase0.Root(header.BodyRoot),
	}
}

func convertSignedBeaconBlockHeader(header *boostTypes.SignedBeaconBlockHeader) *phase0.SignedBeaconBlockHeader {
	return &phase0.SignedBeaconBlockHeader{
		Message:   convertBeaconBlockHeader(header.Header),
		Signature: phase0.BLSSignature(header.Signature),
	}
}

func convertProposerSlashing(slashing *boostTypes.ProposerSlashing) *phase0.ProposerSlashing {
	return &phase0.ProposerSlashing{
		SignedHeader1: convertSignedBeaconBlockHeader(slashing.A),
		SignedHeader2: convertSignedBeaconBlockHeader(slashing.B),
	}
}

func convertAttestationData(data *boostTypes.AttestationData) *phase0.AttestationData {
	return &phase0.AttestationData{
		Slot:            phase0.Slot(data.Slot),
		Index:           phase0.CommitteeIndex(data.Index),
		BeaconBlockRoot: phase0.Root(data.BlockRoot),
		Source: &phase0.Checkpoint{
			Epoch: phase0.Epoch(data.Source.Epoch),
			Root:  phase0.Root(data.Source.Root),
		},
		Target: &phase0.Checkpoint{
			Epoch: phase0.Epoch(data.Target.Epoch),
			Root:  phase0.Root(data.Target.Root),
		},
	}
}

func convertAttestation(attestation *boostTypes.Attestation) *phase0.Attestation {
	return &phase0.Attestation{
		AggregationBits: bitfield.Bitlist(attestation.AggregationBits),
		Data:            convertAttestationData(attestation.Data),
		Signature:       phase0.BLSSignature(attestation.Signature),
	}
}

func convertIndexedAttestation(attestation *boostTypes.IndexedAttestation) *phase0.IndexedAttestation {
	return &phase0.IndexedAttestation{
		AttestingIndices: attestation.AttestingIndices,
		Data:             convertAttestationData(attestation.Data),
		Signature:        phase0.BLSSignature(attestation.Signature),
	}
}

func convertAttesterSlashing(slashing *boostTypes.AttesterSlashing) *phase0.AttesterSlashing {
	return &phase0.AttesterSlashing{
		Attestation1: &phase0.IndexedAttestation{},
		Attestation2: &phase0.IndexedAttestation{},
	}
}

func convertDeposit(deposit *boostTypes.Deposit) *phase0.Deposit {
	return &phase0.Deposit{
		Proof: deposit.Proof,
		Data: &phase0.DepositData{
			PublicKey:             phase0.BLSPubKey(deposit.Data.Pubkey),
			WithdrawalCredentials: deposit.Data.WithdrawalCredentials[:],
			Amount:                phase0.Gwei(deposit.Data.Amount),
			Signature:             phase0.BLSSignature(deposit.Data.Signature),
		},
	}
}

func convertVoluntaryExit(exit *boostTypes.SignedVoluntaryExit) *phase0.SignedVoluntaryExit {
	return &phase0.SignedVoluntaryExit{
		Signature: phase0.BLSSignature(exit.Signature),
		Message: &phase0.VoluntaryExit{
			Epoch:          phase0.Epoch(exit.Message.Epoch),
			ValidatorIndex: phase0.ValidatorIndex(exit.Message.ValidatorIndex),
		},
	}
}

func convertSyncAggregate(syncAggregate *boostTypes.SyncAggregate) *altair.SyncAggregate {
	return &altair.SyncAggregate{
		SyncCommitteeBits:      syncAggregate.CommitteeBits[:],
		SyncCommitteeSignature: phase0.BLSSignature(syncAggregate.CommitteeSignature),
	}
}

func convertBellatrixTransactions(txs []hexutil.Bytes) []bellatrix.Transaction {
	transactions := make([]bellatrix.Transaction, len(txs))

	for i, v := range txs {
		transactions[i] = bellatrix.Transaction(v)
	}

	return transactions
}

func convertBellatrixPayload(payload *boostTypes.ExecutionPayload) *bellatrix.ExecutionPayload {
	return &bellatrix.ExecutionPayload{
		ParentHash:    phase0.Hash32(payload.ParentHash),
		FeeRecipient:  bellatrix.ExecutionAddress(payload.FeeRecipient),
		StateRoot:     payload.StateRoot,
		ReceiptsRoot:  payload.ReceiptsRoot,
		LogsBloom:     payload.LogsBloom,
		PrevRandao:    payload.Random,
		BlockNumber:   payload.BlockNumber,
		GasLimit:      payload.GasLimit,
		GasUsed:       payload.GasUsed,
		Timestamp:     payload.Timestamp,
		ExtraData:     payload.ExtraData,
		BaseFeePerGas: payload.BaseFeePerGas,
		BlockHash:     phase0.Hash32(payload.BlockHash),
		Transactions:  convertBellatrixTransactions(payload.Transactions),
	}
}

// UnblindBellatrixBlock unblinds a blinded Bellatrix beacon block by combining the blinded block with the execution payload
func UnblindBellatrixBlock(signedBlindedBeaconBlock *boostTypes.SignedBlindedBeaconBlock, executionPayload *boostTypes.ExecutionPayload) *bellatrix.SignedBeaconBlock {
	signature := phase0.BLSSignature(signedBlindedBeaconBlock.Signature)

	blindedBeaconBlock := signedBlindedBeaconBlock.Message

	randaoReveal := phase0.BLSSignature(blindedBeaconBlock.Body.RandaoReveal)

	eth1Data := &phase0.ETH1Data{
		DepositRoot:  phase0.Root(blindedBeaconBlock.Body.Eth1Data.DepositRoot),
		DepositCount: blindedBeaconBlock.Body.Eth1Data.DepositCount,
		BlockHash:    blindedBeaconBlock.Body.Eth1Data.BlockHash[:],
	}

	proposerSlashings := make([]*phase0.ProposerSlashing, len(blindedBeaconBlock.Body.ProposerSlashings))
	for i, v := range blindedBeaconBlock.Body.ProposerSlashings {
		proposerSlashings[i] = convertProposerSlashing(v)
	}

	attesterSlashings := make([]*phase0.AttesterSlashing, len(blindedBeaconBlock.Body.AttesterSlashings))
	for i, v := range blindedBeaconBlock.Body.AttesterSlashings {
		attesterSlashings[i] = convertAttesterSlashing(v)
	}

	attestations := make([]*phase0.Attestation, len(blindedBeaconBlock.Body.Attestations))
	for i, v := range blindedBeaconBlock.Body.Attestations {
		attestations[i] = convertAttestation(v)
	}

	deposits := make([]*phase0.Deposit, len(blindedBeaconBlock.Body.Deposits))
	for i, v := range blindedBeaconBlock.Body.Deposits {
		deposits[i] = convertDeposit(v)
	}

	voluntaryExits := make([]*phase0.SignedVoluntaryExit, len(blindedBeaconBlock.Body.VoluntaryExits))
	for i, v := range blindedBeaconBlock.Body.VoluntaryExits {
		voluntaryExits[i] = convertVoluntaryExit(v)
	}

	syncAggregate := convertSyncAggregate(blindedBeaconBlock.Body.SyncAggregate)

	payload := convertBellatrixPayload(executionPayload)

	body := &bellatrix.BeaconBlockBody{
		RANDAOReveal:      randaoReveal,
		ETH1Data:          eth1Data,
		Graffiti:          blindedBeaconBlock.Body.Graffiti,
		ProposerSlashings: proposerSlashings,
		AttesterSlashings: attesterSlashings,
		Attestations:      attestations,
		Deposits:          deposits,
		VoluntaryExits:    voluntaryExits,
		SyncAggregate:     syncAggregate,
		ExecutionPayload:  payload,
	}

	block := &bellatrix.BeaconBlock{
		Slot:          phase0.Slot(blindedBeaconBlock.Slot),
		ProposerIndex: phase0.ValidatorIndex(blindedBeaconBlock.ProposerIndex),
		ParentRoot:    phase0.Root(blindedBeaconBlock.ParentRoot),
		StateRoot:     phase0.Root(blindedBeaconBlock.StateRoot),
		Body:          body,
	}

	return &bellatrix.SignedBeaconBlock{
		Message:   block,
		Signature: signature,
	}
}

// UnblindCapellaBlock unblinds a blinded Capella beacon block by combining the blinded block with the execution payload
func UnblindCapellaBlock(signedBlindedBeaconBlock *capellaApi.SignedBlindedBeaconBlock, executionPayload *capella.ExecutionPayload) *capella.SignedBeaconBlock {
	// dataVersion = eth2spec.DataVersionCapella
	signature := phase0.BLSSignature(signedBlindedBeaconBlock.Signature)

	blindedBeaconBlock := signedBlindedBeaconBlock.Message

	randaoReveal := blindedBeaconBlock.Body.RANDAOReveal

	eth1Data := &phase0.ETH1Data{
		DepositRoot:  blindedBeaconBlock.Body.ETH1Data.DepositRoot,
		DepositCount: blindedBeaconBlock.Body.ETH1Data.DepositCount,
		BlockHash:    blindedBeaconBlock.Body.ETH1Data.BlockHash,
	}

	body := &capella.BeaconBlockBody{
		RANDAOReveal:      randaoReveal,
		ETH1Data:          eth1Data,
		Graffiti:          blindedBeaconBlock.Body.Graffiti,
		ProposerSlashings: blindedBeaconBlock.Body.ProposerSlashings,
		AttesterSlashings: blindedBeaconBlock.Body.AttesterSlashings,
		Attestations:      blindedBeaconBlock.Body.Attestations,
		Deposits:          blindedBeaconBlock.Body.Deposits,
		VoluntaryExits:    blindedBeaconBlock.Body.VoluntaryExits,
		SyncAggregate:     blindedBeaconBlock.Body.SyncAggregate,
		ExecutionPayload:  executionPayload,
	}

	block := &capella.BeaconBlock{
		Slot:          blindedBeaconBlock.Slot,
		ProposerIndex: blindedBeaconBlock.ProposerIndex,
		ParentRoot:    blindedBeaconBlock.ParentRoot,
		StateRoot:     blindedBeaconBlock.StateRoot,
		Body:          body,
	}

	return &capella.SignedBeaconBlock{
		Message:   block,
		Signature: signature,
	}
}

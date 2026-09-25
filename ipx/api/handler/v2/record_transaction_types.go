package v2

import (
	"errors"
	"strconv"
	"strings"

	"github.com/andantan/svmlab/core/codec"
	"github.com/andantan/svmlab/core/types"
)

// RecordCreateAccountRequest funds a new account sized and owned for the SPL Record program -- System
// CreateAccount only, not yet initialized. Initialize it in the same transaction (see
// record/initialize): an uninitialized record account can be initialized by
// anyone, with any authority they like.
type RecordCreateAccountRequest struct {
	// RecordAccount is the account created. It signs alongside RentPayer, since an
	// address does not exist until whoever holds its private key authorizes its
	// creation. It must not already exist.
	RecordAccount string `json:"record_account" example:""`
	// DataLength is how many bytes of data (excluding the 33-byte header) the
	// record should hold. For a 256-bit range proof that is 1064; a proof is
	// verified from record offset 33.
	DataLength string `json:"data_length" example:""`
	// RentPayer funds RecordAccount's creation for exactly the rent-exemption
	// minimum for its size (33 + data_length).
	RentPayer string `json:"rent_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	dataLength    uint64
	rentPayer     *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordCreateAccountRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if v := strings.TrimSpace(r.DataLength); v == "" {
		return errors.New("data_length is required")
	} else if r.dataLength, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("data_length: " + err.Error())
	}
	if r.rentPayer, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RentPayer)); err != nil {
		return errors.New("rent_payer: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordCreateAccountRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordCreateAccountRequest) ToDataLength() uint64               { return r.dataLength }
func (r *RecordCreateAccountRequest) RentPayerKey() *types.PublicKey     { return r.rentPayer }
func (r *RecordCreateAccountRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordCreateAccountRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordCreateAccountRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordCreateAccountResponse reports the built transaction.
type RecordCreateAccountResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount      string `json:"record_account"`
	DataLength         string `json:"data_length"`
	Space              uint64 `json:"space"`
	RentExemptLamports uint64 `json:"rent_exempt_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordCreateAccountResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, dataLength uint64, space uint64, rentExempt uint64,
	fee uint64,
) *RecordCreateAccountResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordCreateAccountResponse{
		Transaction:        codec.Base64.Encode(raw),
		Message:            codec.Base64.Encode(message),
		RecentBlockhash:    tx.Message.RecentBlockhash.Base58(),
		AccountKeys:        keys,
		Signers:            signers,
		NonceAuthority:     nonceAuth,
		RecordAccount:      recordAccount.Base58(),
		DataLength:         strconv.FormatUint(dataLength, 10),
		Space:              space,
		RentExemptLamports: rentExempt,
		Fee:                newSystemPayer(feePayer, fee),
	}
}

// RecordInitializeRequest marks a freshly created record account as a record and names its authority.
type RecordInitializeRequest struct {
	// RecordAccount must already exist, owned by the Record program and at least
	// 33 bytes (see record/create-account), and not yet initialized.
	RecordAccount string `json:"record_account" example:""`
	// Authority is who may later write to, reassign, reallocate, or close the
	// record. It does not sign here, which is why this should land in the same
	// transaction as record/create-account: an uninitialized record account can
	// be initialized by anyone, with any authority they like.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	authority     *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordInitializeRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordInitializeRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordInitializeRequest) AuthorityKey() *types.PublicKey     { return r.authority }
func (r *RecordInitializeRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordInitializeRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordInitializeRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordInitializeResponse reports the built transaction.
type RecordInitializeResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount string `json:"record_account"`
	Authority     string `json:"authority"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordInitializeResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, authority *types.PublicKey,
	fee uint64,
) *RecordInitializeResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordInitializeResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		RecordAccount:   recordAccount.Base58(),
		Authority:       authority.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// RecordWriteRequest copies bytes into a record account at an offset.
type RecordWriteRequest struct {
	// RecordAccount must already be initialized (see record/initialize).
	RecordAccount string `json:"record_account" example:""`
	// Authority is the record's recorded authority. It signs.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	// Offset counts from the end of the record's 33-byte header, not from the
	// start of the account: writing at offset 0 puts the first byte at byte 33.
	// A proof written from offset 0 is verified with proof_offset 33.
	Offset string `json:"offset" example:""`
	// Data is the bytes to write, base58-encoded. It has to fit in one
	// transaction alongside everything else: about 1000 bytes without a durable
	// nonce, about 900 with one. A larger proof is written in several calls,
	// each at its own offset.
	Data string `json:"data" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	authority     *types.PublicKey
	offset        uint64
	data          []byte
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordWriteRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if v := strings.TrimSpace(r.Offset); v == "" {
		return errors.New("offset is required")
	} else if r.offset, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("offset: " + err.Error())
	}
	if v := strings.TrimSpace(r.Data); v == "" {
		return errors.New("data is required")
	} else if r.data, err = codec.Base58.Decode(v); err != nil {
		return errors.New("data: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordWriteRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordWriteRequest) AuthorityKey() *types.PublicKey     { return r.authority }
func (r *RecordWriteRequest) ToOffset() uint64                   { return r.offset }
func (r *RecordWriteRequest) ToData() []byte                     { return r.data }
func (r *RecordWriteRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordWriteRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordWriteRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordWriteResponse reports the built transaction.
type RecordWriteResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount string `json:"record_account"`
	Authority     string `json:"authority"`
	Offset        string `json:"offset"`
	Length        int    `json:"length"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordWriteResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, authority *types.PublicKey, offset uint64, length int,
	fee uint64,
) *RecordWriteResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordWriteResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		RecordAccount:   recordAccount.Base58(),
		Authority:       authority.Base58(),
		Offset:          strconv.FormatUint(offset, 10),
		Length:          length,
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// RecordSetAuthorityRequest hands a record account to a new authority.
type RecordSetAuthorityRequest struct {
	// RecordAccount must already be initialized.
	RecordAccount string `json:"record_account" example:""`
	// Authority is the record's current authority. It signs.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	// NewAuthority becomes the record's authority. It does not sign.
	NewAuthority string `json:"new_authority" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	authority     *types.PublicKey
	newAuthority  *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordSetAuthorityRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.newAuthority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.NewAuthority)); err != nil {
		return errors.New("new_authority: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordSetAuthorityRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordSetAuthorityRequest) AuthorityKey() *types.PublicKey     { return r.authority }
func (r *RecordSetAuthorityRequest) NewAuthorityKey() *types.PublicKey  { return r.newAuthority }
func (r *RecordSetAuthorityRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordSetAuthorityRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordSetAuthorityRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordSetAuthorityResponse reports the built transaction.
type RecordSetAuthorityResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount string `json:"record_account"`
	Authority     string `json:"authority"`
	NewAuthority  string `json:"new_authority"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordSetAuthorityResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, authority *types.PublicKey, newAuthority *types.PublicKey,
	fee uint64,
) *RecordSetAuthorityResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordSetAuthorityResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		RecordAccount:   recordAccount.Base58(),
		Authority:       authority.Base58(),
		NewAuthority:    newAuthority.Base58(),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

// RecordCloseRequest closes a record account and reclaims its lamports.
type RecordCloseRequest struct {
	// RecordAccount must already be initialized.
	RecordAccount string `json:"record_account" example:""`
	// Authority is the record's recorded authority. It signs.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	// Receiver gains the record's lamports.
	Receiver string `json:"receiver" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	authority     *types.PublicKey
	receiver      *types.PublicKey
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordCloseRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if r.receiver, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Receiver)); err != nil {
		return errors.New("receiver: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordCloseRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordCloseRequest) AuthorityKey() *types.PublicKey     { return r.authority }
func (r *RecordCloseRequest) ReceiverKey() *types.PublicKey      { return r.receiver }
func (r *RecordCloseRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordCloseRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordCloseRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordCloseResponse reports the built transaction.
type RecordCloseResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount     string `json:"record_account"`
	Authority         string `json:"authority"`
	Receiver          string `json:"receiver"`
	ReclaimedLamports uint64 `json:"reclaimed_lamports"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordCloseResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, authority *types.PublicKey, receiver *types.PublicKey, reclaimedLamports uint64,
	fee uint64,
) *RecordCloseResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordCloseResponse{
		Transaction:       codec.Base64.Encode(raw),
		Message:           codec.Base64.Encode(message),
		RecentBlockhash:   tx.Message.RecentBlockhash.Base58(),
		AccountKeys:       keys,
		Signers:           signers,
		NonceAuthority:    nonceAuth,
		RecordAccount:     recordAccount.Base58(),
		Authority:         authority.Base58(),
		Receiver:          receiver.Base58(),
		ReclaimedLamports: reclaimedLamports,
		Fee:               newSystemPayer(feePayer, fee),
	}
}

// RecordReallocateRequest grows a record account to hold more data.
type RecordReallocateRequest struct {
	// RecordAccount must already be initialized. It must already hold enough
	// lamports to be rent exempt at the new size: this instruction does not fund
	// it, so top it up with a system transfer first.
	RecordAccount string `json:"record_account" example:""`
	// Authority is the record's recorded authority. It signs.
	Authority string `json:"authority" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`
	// DataLength is how many bytes of data (excluding the 33-byte header) the
	// record should hold afterwards. It does nothing if the account is already
	// that large.
	DataLength string `json:"data_length" example:""`

	// FeePayer signs and pays the transaction fee.
	FeePayer string `json:"fee_payer" example:"EodYvwsT22JTdNmvCeC974WjPiVYcxvfGpYLJxnB3JqK"`

	// RecentBlockhash is always required, and there is no server-side fetch
	// behind it: this builds the message against exactly the value given,
	// which expires whenever the runtime says it does. When
	// DurableNonceAccount is also named, this is not what the message is
	// built against — it is only what prices it, since a nonce is never among
	// the cluster's recent blockhashes and pricing against one directly comes
	// back expired.
	RecentBlockhash string `json:"recent_blockhash" example:""`

	// DurableNonceAccount may be left empty, in which case the message is
	// built against RecentBlockhash directly and expires with it. Naming one
	// builds the message against the value that account stores instead, so it
	// never expires, and prepends the advance that consumes it; RecentBlockhash
	// is then used only to price the transaction.
	DurableNonceAccount string `json:"durable_nonce_account" example:""`

	recordAccount *types.PublicKey
	authority     *types.PublicKey
	dataLength    uint64
	fp            *types.PublicKey
	rbh           *types.Hash
	dna           *types.PublicKey
}

func (r *RecordReallocateRequest) ValidateRequest() error {
	var err error

	if r.recordAccount, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.RecordAccount)); err != nil {
		return errors.New("record_account: " + err.Error())
	}
	if r.authority, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.Authority)); err != nil {
		return errors.New("authority: " + err.Error())
	}
	if v := strings.TrimSpace(r.DataLength); v == "" {
		return errors.New("data_length is required")
	} else if r.dataLength, err = strconv.ParseUint(v, 10, 64); err != nil {
		return errors.New("data_length: " + err.Error())
	}
	if r.fp, err = types.NewPublicKeyFromBase58(strings.TrimSpace(r.FeePayer)); err != nil {
		return errors.New("fee_payer: " + err.Error())
	}

	rb := strings.TrimSpace(r.RecentBlockhash)
	if rb == "" {
		return errors.New("recent_blockhash is required")
	}
	if r.rbh, err = types.NewHashFromBase58(rb); err != nil {
		return errors.New("recent_blockhash: " + err.Error())
	}

	if dn := strings.TrimSpace(r.DurableNonceAccount); dn != "" {
		if r.dna, err = types.NewPublicKeyFromBase58(dn); err != nil {
			return errors.New("durable_nonce_account: " + err.Error())
		}
	}

	return nil
}

func (r *RecordReallocateRequest) RecordAccountKey() *types.PublicKey { return r.recordAccount }
func (r *RecordReallocateRequest) AuthorityKey() *types.PublicKey     { return r.authority }
func (r *RecordReallocateRequest) ToDataLength() uint64               { return r.dataLength }
func (r *RecordReallocateRequest) FeePayerKey() *types.PublicKey      { return r.fp }
func (r *RecordReallocateRequest) Blockhash() *types.Hash             { return r.rbh }
func (r *RecordReallocateRequest) DurableNonceAccountKey() *types.PublicKey {
	return r.dna
}

// RecordReallocateResponse reports the built transaction.
type RecordReallocateResponse struct {
	Transaction     string   `json:"transaction"`
	Message         string   `json:"message"`
	RecentBlockhash string   `json:"recent_blockhash"`
	AccountKeys     []string `json:"account_keys"`
	Signers         []string `json:"signers"`

	NonceAuthority string `json:"nonce_authority,omitempty"`

	RecordAccount string `json:"record_account"`
	Authority     string `json:"authority"`
	DataLength    string `json:"data_length"`

	Fee SystemPayer `json:"fee"`
}

func NewRecordReallocateResponse(
	tx *types.Transaction, raw, message []byte,
	feePayer, nonceAuthority *types.PublicKey,
	recordAccount *types.PublicKey, authority *types.PublicKey, dataLength uint64,
	fee uint64,
) *RecordReallocateResponse {
	nonceAuth := ""
	if !nonceAuthority.IsNil() {
		nonceAuth = nonceAuthority.Base58()
	}

	keys := make([]string, len(tx.Message.AccountKeys))
	for i, k := range tx.Message.AccountKeys {
		keys[i] = k.Base58()
	}

	signers := make([]string, tx.Message.NumSigners())
	for i, k := range tx.Message.Signers() {
		signers[i] = k.Base58()
	}

	return &RecordReallocateResponse{
		Transaction:     codec.Base64.Encode(raw),
		Message:         codec.Base64.Encode(message),
		RecentBlockhash: tx.Message.RecentBlockhash.Base58(),
		AccountKeys:     keys,
		Signers:         signers,
		NonceAuthority:  nonceAuth,
		RecordAccount:   recordAccount.Base58(),
		Authority:       authority.Base58(),
		DataLength:      strconv.FormatUint(dataLength, 10),
		Fee:             newSystemPayer(feePayer, fee),
	}
}

package phone

import (
	"errors"
	"log/slog"
	"strings"
	"unicode"

	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/storage"
)

// phoneServer is the gRPC server implementation for the Phone service.
type phoneServer struct {
	phoneStore   storage.PhoneStore
	profileStore storage.ProfileStore
	xrefStore    storage.XrefStore

	logger *slog.Logger

	api.UnimplementedPhonesServer
}

// NewPhoneServer creates a new instance of the gRPC Phone server, returning
// a pointer to a concrete implementation of the PhonesServer interface.
func NewPhoneServer(
	phoneSql storage.PhoneStore,
	profileSql storage.ProfileStore,
	xrefSql storage.XrefStore,
) api.PhonesServer {

	return &phoneServer{
		phoneStore:   phoneSql,
		profileStore: profileSql,
		xrefStore:    xrefSql,
		logger: slog.Default().
			With(slog.String(definitions.ComponentKey, definitions.ComponentPhoneServer)).
			With(slog.String(definitions.PackageKey, definitions.PackagePhone)),
	}
}

// NormalizePhoneNumber normalizes the phone number field of a PhoneUpsert request model,
// removing all non-digit characters.
func normalizePhoneNumber(ph string) string {

	var normalized strings.Builder

	// Remove all non-digit characters from the phone number
	for _, r := range ph {
		if unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}

	return normalized.String()
}

// NormalizeCountryCode normalizes the country code field of a PhoneUpsert request model,
// removing all non-digit characters.
func normalizeCountryCode(cc string) string {

	var normalized strings.Builder

	// Remove all non-digit characters from the country code
	for _, r := range cc {
		if unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}

	return normalized.String()
}

// NormalizeExtension normalizes the extension field of a PhoneUpsert request model,
// removing all non-digit characters.
func normalizeExtension(ext string) string {

	var normalized strings.Builder

	// Remove all non-digit characters from the extension
	for _, r := range ext {
		if unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}

	return normalized.String()
}

// PhoneUpsert provides functions to access data in phone record creation or update operations request models.
type PhoneUpsert interface {
	GetCountryCode() string
	GetExtension() string
	GetPhoneNumber() string
	GetPhoneType() api.PhoneType
	GetUsername() string
}

// ValidateCmd validates the fields of a PhoneUpsert request model.
func ValidateCmd(cmd PhoneUpsert) error {

	if err := validate.IsValidEmail(cmd.GetUsername()); err != nil {
		return err
	}

	if err := validate.IsValidCountryCode(normalizeCountryCode(cmd.GetCountryCode())); err != nil {
		return err
	}

	if err := validate.IsValidPhoneNumber(normalizePhoneNumber(cmd.GetPhoneNumber())); err != nil {
		return err
	}

	_, ok := api.PhoneType_name[int32(cmd.GetPhoneType())]
	if !ok {
		return errors.New("invalid phone type")
	}

	// this can happen either if the field isnt set or there was a failure to convert it to a valid enum value
	if cmd.GetPhoneType() == api.PhoneType_PHONE_TYPE_UNSPECIFIED {
		return errors.New("phone type may not be 'unspecified'")
	}

	return nil
}

// ConvertPhoneType converts a string representation of a phone type to the corresponding v1.PhoneType enum value.
func ConvertPhoneType(pt string) api.PhoneType {

	// captialize string
	pt = strings.TrimSpace(strings.ToUpper(pt))

	// check for enum prefix
	if !strings.HasPrefix(pt, "PHONE_TYPE_") {
		pt = "PHONE_TYPE_" + pt
	}

	phEnum, ok := api.PhoneType_value[pt]
	if !ok {
		// defaults to unspecified
		return api.PhoneType_PHONE_TYPE_UNSPECIFIED
	}

	return api.PhoneType(phEnum)
}

func convertToSqlString(pt api.PhoneType) string {

	tp := pt.String()

	// if has prefix, remove
	if after, ok := strings.CutPrefix(tp, "PHONE_TYPE_"); ok {
		tp = after
	}

	return strings.ToLower(tp)
}

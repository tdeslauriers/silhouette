package profile

import (
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tdeslauriers/carapace/pkg/validate"
	api "github.com/tdeslauriers/silhouette/api/v1"
	"github.com/tdeslauriers/silhouette/internal/definitions"
	"github.com/tdeslauriers/silhouette/internal/storage"
)

// profileServer is the gRPC server implementation for the Profile service.
type profileServer struct {
	profileStore storage.ProfileStore

	logger *slog.Logger

	api.UnimplementedProfilesServer
}

func NewProfileServer(profileStore storage.ProfileStore) api.ProfilesServer {

	return &profileServer{
		profileStore: profileStore,
		logger: slog.Default().
			With(slog.String(definitions.ComponentKey, definitions.ComponentProfileServer)).
			With(slog.String(definitions.PackageKey, definitions.PackageProfile)),
	}
}

// ProfileUpsert provides functions to access data in an profile record creation or update operations request models
type ProfileUpsert interface {
	GetUsername() string
	GetNickName() string
	GetDarkMode() bool
}

// ValidateCmd validates the fields of a ProfileUpsert request model
func ValidateCmd(cmd ProfileUpsert) error {

	// validate email
	if err := validate.IsValidEmail(strings.TrimSpace(cmd.GetUsername())); err != nil {
		return err
	}

	// if nickname provided, validate it
	if len(strings.TrimSpace(cmd.GetNickName())) > 0 {
		if err := ValidateNickname(strings.TrimSpace(cmd.GetNickName())); err != nil {
			return err
		}
	}

	return nil
}

// NicknameRegex allows letters (including international), numbers, spaces, and common punctuation
// excludes control characters and null bytes by being an explicit allow-list
var NicknameRegex = regexp.MustCompile(`^[\p{L}\p{N}\s._'-]+$`)

// ValidateNickname validates the nickname field of a profile record, ensuring
// it meets length and character requirements.
func ValidateNickname(nickname string) error {

	// Trim whitespace
	nickname = strings.TrimSpace(nickname)

	// If provided, check length bounds
	if utf8.RuneCountInString(nickname) < 2 {
		return errors.New("nickname must be at least 2 characters")
	}

	if utf8.RuneCountInString(nickname) > 50 {
		return errors.New("nickname must be 50 characters or less")
	}

	// Check against allowed character set
	if !NicknameRegex.MatchString(nickname) {
		return errors.New("nickname contains invalid characters (only letters, numbers, spaces, dots, underscores, hyphens, and apostrophes allowed)")
	}

	// Optional: prevent excessive spaces
	if strings.Contains(nickname, "  ") {
		return errors.New("nickname cannot contain consecutive spaces")
	}

	return nil
}

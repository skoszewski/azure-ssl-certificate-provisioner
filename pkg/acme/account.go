package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"azure-ssl-certificate-provisioner/internal/types"
)

const (
	baseAccountsRootFolderName = "accounts"
	baseKeysFolderName         = "keys"
	accountFileName            = "account.json"
	filePerm                   = 0600
)

// AccountStorage handles ACME account persistence
type AccountStorage struct {
	email           string
	serverURL       string
	rootPath        string
	rootUserPath    string
	keysPath        string
	accountFilePath string
}

// NewAccountStorage creates a new lego-compatible AccountStorage
func NewAccountStorage(email, serverURL string) (*AccountStorage, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}

	// Parse server URL to create directory name (replicate lego's logic)
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %v", err)
	}

	rootPath := filepath.Join(homeDir, ".lego", baseAccountsRootFolderName)
	serverPath := strings.NewReplacer(":", "_", "/", string(os.PathSeparator)).Replace(parsedURL.Host)
	accountsPath := filepath.Join(rootPath, serverPath)
	rootUserPath := filepath.Join(accountsPath, email)

	return &AccountStorage{
		email:           email,
		serverURL:       serverURL,
		rootPath:        rootPath,
		rootUserPath:    rootUserPath,
		keysPath:        filepath.Join(rootUserPath, baseKeysFolderName),
		accountFilePath: filepath.Join(rootUserPath, accountFileName),
	}, nil
}

// ExistsAccountFilePath checks if account file exists
func (s *AccountStorage) ExistsAccountFilePath() bool {
	if _, err := os.Stat(s.accountFilePath); os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Printf("Error checking account file: %v", err)
		return false
	}
	return true
}

// Save saves account data to disk
func (s *AccountStorage) Save(account *types.Account) error {
	// Create directory structure
	if err := s.createUserFolder(); err != nil {
		return err
	}

	// Save account.json
	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal account data: %v", err)
	}

	if err := os.WriteFile(s.accountFilePath, jsonBytes, filePerm); err != nil {
		return fmt.Errorf("failed to write account file: %v", err)
	}

	log.Printf("Saved ACME account data to: %s", s.accountFilePath)
	return nil
}

// LoadAccount loads account data from disk
func (s *AccountStorage) LoadAccount(privateKey crypto.PrivateKey) (*types.Account, error) {
	fileBytes, err := os.ReadFile(s.accountFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not load account file: %v", err)
	}

	var account types.Account
	if err := json.Unmarshal(fileBytes, &account); err != nil {
		return nil, fmt.Errorf("could not parse account file: %v", err)
	}

	account.SetPrivateKey(privateKey)
	return &account, nil
}

// GetPrivateKey loads or generates a private key
func (s *AccountStorage) GetPrivateKey(keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	keyFilePath := filepath.Join(s.keysPath, s.email+".key")

	// Try to load existing key
	if _, err := os.Stat(keyFilePath); err == nil {
		return s.loadPrivateKey(keyFilePath)
	}

	// Generate new key
	log.Printf("No key found for account %s. Generating a %s key.", s.email, keyType)
	if err := s.createKeysFolder(); err != nil {
		return nil, err
	}

	privateKey, err := s.generatePrivateKey(keyFilePath, keyType)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %v", err)
	}

	log.Printf("Saved key to %s", keyFilePath)
	return privateKey, nil
}

func (s *AccountStorage) createUserFolder() error {
	return os.MkdirAll(s.rootUserPath, 0700)
}

func (s *AccountStorage) createKeysFolder() error {
	return os.MkdirAll(s.keysPath, 0700)
}

func (s *AccountStorage) generatePrivateKey(file string, keyType certcrypto.KeyType) (crypto.PrivateKey, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(keyType)
	if err != nil {
		return nil, err
	}

	certOut, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	defer certOut.Close()

	pemKey := certcrypto.PEMBlock(privateKey)
	if err := pem.Encode(certOut, pemKey); err != nil {
		return nil, err
	}

	// Set file permissions to owner read/write only
	if err := os.Chmod(file, filePerm); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (s *AccountStorage) loadPrivateKey(file string) (crypto.PrivateKey, error) {
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block from key file")
	}

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unknown private key type: %s", keyBlock.Type)
	}
}

// LoadOrCreateAccount loads existing account or creates a new one
func LoadOrCreateAccount(email, serverURL string) (*types.AcmeUser, error) {
	// Create lego-compatible account storage
	accountsStorage, err := NewAccountStorage(email, serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create accounts storage: %v", err)
	}

	// Try to load existing account
	if accountsStorage.ExistsAccountFilePath() {
		log.Printf("Loading existing ACME account for %s", email)

		// Load private key
		privateKey, err := accountsStorage.GetPrivateKey(certcrypto.RSA2048)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %v", err)
		}

		// Load account data
		account, err := accountsStorage.LoadAccount(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load account: %v", err)
		}

		user := &types.AcmeUser{
			Email:        account.Email,
			Registration: account.Registration,
		}
		user.SetPrivateKey(account.GetPrivateKey())
		return user, nil
	}

	// Create new account
	log.Printf("Creating new ACME account for %s", email)

	privateKey, err := accountsStorage.GetPrivateKey(certcrypto.RSA2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	user := &types.AcmeUser{Email: email}
	user.SetPrivateKey(privateKey)
	return user, nil
}

// SaveAccountData saves ACME account data to disk
func SaveAccountData(user *types.AcmeUser, serverURL string) error {
	// Create lego-compatible account storage
	accountsStorage, err := NewAccountStorage(user.Email, serverURL)
	if err != nil {
		return fmt.Errorf("failed to create accounts storage: %v", err)
	}

	// Convert AcmeUser to Account for saving
	account := &types.Account{
		Email:        user.Email,
		Registration: user.Registration,
	}
	account.SetPrivateKey(user.GetPrivateKey())

	return accountsStorage.Save(account)
}

// RegisterAccount registers a new ACME account
func RegisterAccount(user *types.AcmeUser, client *lego.Client) error {
	log.Printf("Registering new ACME account...")
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %v", err)
	}
	user.SetRegistration(reg)
	return nil
}

package wxbizjsonmsgcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Custom error types for WeChat message encryption/decryption
var (
	ErrValidateSignature = fmt.Errorf("validate signature error")
	ErrParseJSON         = fmt.Errorf("parse json error")
	ErrComputeSignature  = fmt.Errorf("compute signature error")
	ErrIllegalAESKey     = fmt.Errorf("illegal aes key")
	ErrValidateCorpID    = fmt.Errorf("validate corpid error")
	ErrEncryptAES        = fmt.Errorf("encrypt aes error")
	ErrDecryptAES        = fmt.Errorf("decrypt aes error")
	ErrIllegalBuffer     = fmt.Errorf("illegal buffer")
	ErrEncodeBase64      = fmt.Errorf("encode base64 error")
	ErrDecodeBase64      = fmt.Errorf("decode base64 error")
	ErrGenReturnJSON     = fmt.Errorf("generate return json error")
)

// generateSHA1 generates a secure signature using SHA1 algorithm
func generateSHA1(token, timestamp, nonce, encrypt string) string {
	// Sort the parameters
	sortList := []string{token, timestamp, nonce, encrypt}
	sort.Strings(sortList)

	// Calculate SHA1 hash
	sha := sha1.New()
	sha.Write([]byte(strings.Join(sortList, "")))
	return fmt.Sprintf("%x", sha.Sum(nil))
}

// extractEncryptedMessage extracts encrypted message from JSON data package
func extractEncryptedMessage(jsonText []byte) (string, error) {
	var jsonDict map[string]interface{}
	if err := json.Unmarshal(jsonText, &jsonDict); err != nil {
		return "", fmt.Errorf("%w: %v", ErrParseJSON, err)
	}

	encrypt, ok := jsonDict["encrypt"].(string)
	if !ok {
		return "", ErrParseJSON
	}

	return encrypt, nil
}

// generateResponseJSON generates JSON message response
func generateResponseJSON(encrypt, signature, timestamp, nonce string) string {
	const template = `{
    "encrypt": "%s",
    "msgsignature": "%s",
    "timestamp": "%s",
    "nonce": "%s"
}`
	return fmt.Sprintf(template, encrypt, signature, timestamp, nonce)
}

// PKCS7Encoder provides encryption/decryption interfaces based on PKCS7 algorithm
type PKCS7Encoder struct {
	blockSize int
}

// NewPKCS7Encoder creates a new PKCS7Encoder
func NewPKCS7Encoder() *PKCS7Encoder {
	return &PKCS7Encoder{blockSize: 32}
}

// Encode performs padding on plaintext that needs to be encrypted
func (p *PKCS7Encoder) Encode(text []byte) []byte {
	textLength := len(text)
	// Calculate the number of bits to pad
	amountToPad := p.blockSize - (textLength % p.blockSize)
	if amountToPad == 0 {
		amountToPad = p.blockSize
	}
	// Get the character used for padding
	pad := make([]byte, amountToPad)
	for i := range pad {
		pad[i] = byte(amountToPad)
	}
	return append(text, pad...)
}

// Decode removes padding characters from decrypted plaintext
func (p *PKCS7Encoder) Decode(decrypted []byte) []byte {
	if len(decrypted) == 0 {
		return decrypted
	}

	pad := int(decrypted[len(decrypted)-1])
	if pad < 1 || pad > 32 {
		pad = 0
	}
	if pad > len(decrypted) {
		return decrypted
	}
	return decrypted[:len(decrypted)-pad]
}

// Prpcrypt provides encryption/decryption interfaces for receiving and pushing WeChat messages
type Prpcrypt struct {
	key []byte
}

// NewPrpcrypt creates a new Prpcrypt instance
func NewPrpcrypt(key []byte) *Prpcrypt {
	return &Prpcrypt{key: key}
}

// Encrypt encrypts plaintext
func (p *Prpcrypt) Encrypt(text []byte, receiveID string) ([]byte, error) {
	// Add 16-bit random string to the beginning of plaintext
	randomStr := p.getRandomStr()
	textBytes := text

	// Create buffer with random string + length + text + receiveid
	var buffer []byte
	buffer = append(buffer, []byte(randomStr)...)

	// Add length as 4-byte big-endian integer
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(textBytes)))
	buffer = append(buffer, lengthBytes...)
	buffer = append(buffer, textBytes...)
	buffer = append(buffer, []byte(receiveID)...)

	// Use custom padding method to pad plaintext
	pkcs7 := NewPKCS7Encoder()
	paddedText := pkcs7.Encode(buffer)

	// Encrypt
	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptAES, err)
	}

	iv := p.key[:aes.BlockSize]
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(paddedText))
	mode.CryptBlocks(ciphertext, paddedText)

	// Use BASE64 to encode the encrypted string
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)

	return encoded, nil
}

// Decrypt decrypts ciphertext and removes padding
func (p *Prpcrypt) Decrypt(text, receiveID string) (string, error) {
	// Decode BASE64 first
	encrypted, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecodeBase64, err)
	}

	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptAES, err)
	}

	iv := p.key[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt
	plaintext := make([]byte, len(encrypted))
	mode.CryptBlocks(plaintext, encrypted)

	// Remove padding
	pkcs7 := NewPKCS7Encoder()
	unpaddedText := pkcs7.Decode(plaintext)

	if len(unpaddedText) < 20 {
		return "", ErrIllegalBuffer
	}

	// Remove 16-bit random string
	content := unpaddedText[16:]
	if len(content) < 4 {
		return "", ErrIllegalBuffer
	}

	// Extract JSON length
	jsonLen := binary.BigEndian.Uint32(content[:4])
	if len(content) < int(4+jsonLen) {
		return "", ErrIllegalBuffer
	}

	// Extract JSON content
	jsonContent := string(content[4 : 4+jsonLen])
	fromReceiveID := string(content[4+jsonLen:])

	if fromReceiveID != receiveID {
		return "", ErrValidateCorpID
	}

	return jsonContent, nil
}

// getRandomStr randomly generates 16-bit string
func (p *Prpcrypt) getRandomStr() string {
	// Generate random number between 1000000000000000 and 9999999999999999
	min := big.NewInt(1000000000000000)
	max := big.NewInt(9999999999999999)

	n, err := rand.Int(rand.Reader, new(big.Int).Sub(max, min))
	if err != nil {
		// Fallback to simple random generation
		return fmt.Sprintf("%016d", mathrand.Int63n(10000000000000000))
	}

	return fmt.Sprintf("%016d", new(big.Int).Add(n, min).Int64())
}

// WXBizJsonMsgCrypt is the main struct for WeChat message encryption/decryption
type WXBizJsonMsgCrypt struct {
	key       []byte
	token     string
	receiveID string
}

// NewWXBizJsonMsgCrypt creates a new WXBizJsonMsgCrypt instance
func NewWXBizJsonMsgCrypt(token, encodingAESKey, receiveID string) (*WXBizJsonMsgCrypt, error) {
	key, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encodingAESKey", ErrIllegalAESKey)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("%w: invalid encodingAESKey length", ErrIllegalAESKey)
	}

	return &WXBizJsonMsgCrypt{
		key:       key,
		token:     token,
		receiveID: receiveID,
	}, nil
}

// VerifyURL verifies URL parameters
func (w *WXBizJsonMsgCrypt) VerifyURL(msgSignature, timestamp, nonce, echoStr string) (string, error) {
	signature := generateSHA1(w.token, timestamp, nonce, echoStr)

	if signature != msgSignature {
		return "", ErrValidateSignature
	}

	pc := NewPrpcrypt(w.key)
	replyEchoStr, err := pc.Decrypt(echoStr, w.receiveID)
	if err != nil {
		return "", err
	}

	return replyEchoStr, nil
}

// EncryptMsg encrypts and packages enterprise reply messages to users
func (w *WXBizJsonMsgCrypt) EncryptMsg(replyMsg []byte, nonce string, timestamp ...string) (string, error) {
	pc := NewPrpcrypt(w.key)
	encrypt, err := pc.Encrypt(replyMsg, w.receiveID)
	if err != nil {
		return "", err
	}

	encryptStr := string(encrypt)

	ts := ""
	if len(timestamp) > 0 && timestamp[0] != "" {
		ts = timestamp[0]
	} else {
		ts = strconv.FormatInt(time.Now().Unix(), 10)
	}

	// Generate secure signature
	signature := generateSHA1(w.token, ts, nonce, encryptStr)

	return generateResponseJSON(encryptStr, signature, ts, nonce), nil
}

// DecryptMsg verifies message authenticity and gets decrypted plaintext
func (w *WXBizJsonMsgCrypt) DecryptMsg(msgSignature, timestamp, nonce string, postData []byte) (string, error) {
	// Extract encrypted message from JSON
	encrypt, err := extractEncryptedMessage(postData)
	if err != nil {
		return "", err
	}

	// Verify secure signature
	signature := generateSHA1(w.token, timestamp, nonce, encrypt)

	if signature != msgSignature {
		return "", ErrValidateSignature
	}

	// Decrypt the message
	pc := NewPrpcrypt(w.key)
	jsonContent, err := pc.Decrypt(encrypt, w.receiveID)
	if err != nil {
		return "", err
	}

	return jsonContent, nil
}

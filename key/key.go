package key

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// formatForFile returns the file format (either from flags or
// based on file extension).
var fileExtToFormat = map[string]string{
	".pem": "PEM",
	".crt": "PEM",
	".p7b": "PEM",
	".p7c": "PEM",
	//".p12":   "PKCS12",
	//".pfx":   "PKCS12",
	//".jceks": "JCEKS",
	//".jks":   "JCEKS", // Only partially supported
	".der": "DER",
}

func ReadPrivateKey(file *os.File, format string, password func(string) string, callback func(key *rsa.PrivateKey)) error {
	reader := bufio.NewReaderSize(file, 4)
	filename := file.Name()
	format, err := formatForFile(reader, filename, format)
	if err != nil {
		return fmt.Errorf("unable to guess file type (for file %s)\n", filename)
	}

	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			buf := block.Bytes
			if x509.IsEncryptedPEMBlock(block) {
				buf, err = x509.DecryptPEMBlock(block, []byte(password("")))
				if err != nil {
					return fmt.Errorf("error parsing password protected private key from PEM data\n")
				}
			}
			err = parsePKCS(buf, callback)
			if err != nil {
				return fmt.Errorf("error parsing private key from PEM data\n")
			}
		}
	case "DER":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("error reading input: %s\n", err)
		}
		err = parsePKCS(data, callback)
		if err != nil {
			return fmt.Errorf("error parsing private key from DER data\n")
		}
		//case "PKCS12":
		//	data, err := ioutil.ReadAll(reader)
		//	if err != nil {
		//		return fmt.Errorf("error reading input: %s\n", err)
		//	}
		//	privateKey, _, err := pkcs12.Decode(data, password(""))
		//	if err == nil {
		//		callback(privateKey)
		//	}
		//case "JCEKS":
		//	ks, err := jceks.LoadFromReader(reader, []byte(password("")))
		//	if err != nil {
		//		return fmt.Errorf("error parsing keystore: %s\n", err)
		//	}
		//	for _, alias := range ks.ListPrivateKeys() {
		//		privateKey, _, err := ks.GetPrivateKeyAndCerts(alias, []byte(password(alias)))
		//		if err != nil {
		//			return fmt.Errorf("error parsing keystore: %s\n", err)
		//		}
		//		callback(privateKey)
		//	}
	}
	return fmt.Errorf("unknown file type: %s\n", format)
}

func parsePKCS(data []byte, callback func(key *rsa.PrivateKey)) error {
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(data)
	if err == nil {
		callback(rsaPrivateKey)
		return nil
	}
	return fmt.Errorf("error parsing PKCS private key\n")
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func formatForFile(file *bufio.Reader, filename, format string) (string, error) {
	// First, honor --format flag we got from user
	if format != "" {
		return format, nil
	}

	// Second, attempt to guess based on extension
	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, nil
	}

	// Third, attempt to guess based on first 4 bytes of input
	data, err := file.Peek(4)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %s\n", err)
	}

	// Heuristics for guessing -- best effort.
	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		// JCEKS/JKS files always start with this prefix
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		// Starts with '----' or 'CONN' (what s_client prints...)
		return "PEM", nil
	}
	if magic&0xFFFF0000 == 0x30820000 {
		// Looks like the input is DER-encoded, so it's either PKCS12 or X.509.
		if magic&0x0000FF00 == 0x0300 {
			// Probably X.509
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", fmt.Errorf("unable to guess file format")
}

// pemScanner will return a bufio.Scanner that splits the input
// from the given reader into PEM blocks.
func pemScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}

		return 0, nil, nil
	})

	return scanner
}

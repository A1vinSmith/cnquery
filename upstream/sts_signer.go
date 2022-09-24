package upstream

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/ranger-rpc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"google.golang.org/protobuf/proto"
)

func ExchangeSSHKey(apiEndpoint string, identityMrn string, resourceMrn string) (*ServiceAccountCredentials, error) {
	stsClient, err := NewSecureTokenServiceClient(apiEndpoint, ranger.DefaultHttpClient())
	if err != nil {
		return nil, err
	}

	claims := &Claims{
		Subject:  identityMrn,
		Resource: resourceMrn,
		Exp:      time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		Iat:      time.Now().Format(time.RFC3339),
	}

	// TODO: reuse ssh provider package
	signers := []ssh.Signer{}
	if sshAgentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		log.Debug().Str("socket", os.Getenv("SSH_AUTH_SOCK")).Msg("ssh agent socket found")
		sshAgentClient := agent.NewClient(sshAgentConn)
		sshAgentSigners, err := sshAgentClient.Signers()
		if err == nil && len(sshAgentSigners) == 0 {
			log.Warn().Msg("could not find keys in ssh agent")
		} else if err == nil {
			signers = append(signers, sshAgentSigners...)
		} else {
			log.Error().Err(err).Msg("could not get public keys from ssh agent")
		}
	} else {
		log.Debug().Msg("could not find valud ssh agent authentication")
	}

	signatures, err := signClaims(claims, signers...)
	if err != nil {
		return nil, err
	}

	resp, err := stsClient.ExchangeSSH(context.Background(), &ExchangeSSHKeyRequest{
		Claims:     claims,
		Signatures: signatures,
	})
	if err != nil {
		return nil, err
	}
	return &ServiceAccountCredentials{
		Mrn:         resp.Mrn,
		ParentMrn:   resp.ParentMrn,
		PrivateKey:  resp.PrivateKey,
		Certificate: resp.Certificate,
		ApiEndpoint: resp.ApiEndpoint,
	}, nil
}

func signClaims(claims *Claims, signer ...ssh.Signer) ([]*SshSignature, error) {
	data, err := proto.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return sign(data, signer)
}

// sign implements claims signing with ssh.Signer
//
// To generate a new SSH key use:
// ssh-keygen -t ed25519 -C "your_email@example.com"
func sign(data []byte, signer []ssh.Signer) ([]*SshSignature, error) {
	signatures := make([]*SshSignature, 0, len(signer))
	for i := range signer {
		sig := signer[i]

		// sign content
		sshSign, err := sig.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}

		signatures = append(signatures, &SshSignature{
			Alg: "x5t#S256",
			Kid: ssh.FingerprintSHA256(sig.PublicKey()),
			Sig: hex.EncodeToString(ssh.Marshal(sshSign)),
		})
	}
	return signatures, nil
}

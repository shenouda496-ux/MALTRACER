// smtp_config.go

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"os"
	"path/filepath"
)

var (
	smtpHost   = "smtp.gmail.com:587"
	smtpFrom   = getEnv("SMTP_FROM", "mo6633ya@gmail.com")
	smtpPass   = getEnv("SMTP_PASS", "zyrceywoepgxvvcl")
	adminEmail = getEnv("ADMIN_EMAIL", "moelmad.contactme@gmail.com")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run mail.go <Subject> <Body> [OptionalAttachmentPath]")
		os.Exit(1)
	}

	subject := os.Args[1]
	body := os.Args[2]
	attachmentPath := ""
	if len(os.Args) >= 4 {
		attachmentPath = os.Args[3]
	}

	smtpAuth := smtp.PlainAuth("", smtpFrom, smtpPass, "smtp.gmail.com")
	boundary := "MALTRACER_BOUNDARY_12345"

	var msg bytes.Buffer
	msg.WriteString("From: " + smtpFrom + "\r\n")
	msg.WriteString("To: " + adminEmail + "\r\n")
	msg.WriteString("Subject: " + subject + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\r\n")
	msg.WriteString("\r\n--" + boundary + "\r\n")
	msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
	msg.WriteString(body + "\r\n")

	if attachmentPath != "" {
		fileContent, err := os.ReadFile(attachmentPath)
		if err == nil {
			filename := filepath.Base(attachmentPath)
			encoded := base64.StdEncoding.EncodeToString(fileContent)

			msg.WriteString("\r\n--" + boundary + "\r\n")
			msg.WriteString("Content-Type: application/octet-stream; name=\"" + filename + "\"\r\n")
			msg.WriteString("Content-Transfer-Encoding: base64\r\n")
			msg.WriteString("Content-Disposition: attachment; filename=\"" + filename + "\"\r\n\r\n")

			// Line wrap base64
			for i := 0; i < len(encoded); i += 76 {
				end := i + 76
				if end > len(encoded) {
					end = len(encoded)
				}
				msg.WriteString(encoded[i:end] + "\r\n")
			}
		} else {
			fmt.Println("Warning: Failed to read attachment:", err)
		}
	}

	msg.WriteString("\r\n--" + boundary + "--\r\n")

	err := smtp.SendMail(smtpHost, smtpAuth, smtpFrom, []string{adminEmail}, msg.Bytes())
	if err != nil {
		fmt.Println("Failed to send email:", err)
		os.Exit(1)
	}

	fmt.Println("Email sent successfully")
}

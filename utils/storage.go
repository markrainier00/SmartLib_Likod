package utils

import (
	"os"
	"strings"

	storage_go "github.com/supabase-community/storage-go"
)

func DeleteSchoolIDImage(imageURL string) error {
	if imageURL == "" {
		return nil
	}

	// extract filename from the full URL
	// URL format: https://.../storage/v1/object/public/school-id-images/FILENAME
	parts := strings.Split(imageURL, "/school-id-images/")
	if len(parts) < 2 {
		return nil
	}
	filename := parts[1]

	client := storage_go.NewClient(
		os.Getenv("DB_URL")+"/storage/v1",
		os.Getenv("DB_SERVICE_KEY"),
		nil,
	)

	_, err := client.RemoveFile("school-id-images", []string{filename})
	return err
}

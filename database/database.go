package database

import (
	"fmt"
	"log"
	"os"

	"SmartLib_Likod/model" // 🚀 IDINAGDAG: Kailangan ito para makilala ng Go ang mga Structs mo

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	dsn := os.Getenv("DATABASE_URL")

	if dsn == "" {
		host := os.Getenv("DB_HOST")
		user := os.Getenv("DB_USER")
		password := os.Getenv("DB_PASSWORD")
		dbname := os.Getenv("DB_NAME")
		port := os.Getenv("DB_PORT")

		dsn = fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
			host, user, password, dbname, port)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database. Check your .env file! Error: ", err)
	}

	fmt.Println("Database connected successfully!")

	// 🚀 STEP 4: AUTOMIGRATE (DITO GAGAWAIN ANG MGA TABLES SA SUPABASE)
	// Kapag nag-go run main.go ka, babasahin niya ito at gagawa ng tables kung wala pa.
	err = db.AutoMigrate(
		&model.Conversation{}, // Gagawa ng 'conversations' table para sa chat
		&model.Message{},      // Gagawa ng 'messages' table para sa chat

		// (Optional) Kung gusto mong automatic din niyang i-update ang ibang tables mo:
		// &model.Book{},
		// &model.User{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database tables! Error: ", err)
	}
	fmt.Println("Database tables migrated successfully!")

	DB = db
}

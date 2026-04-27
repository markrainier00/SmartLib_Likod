package services

import (
	"fmt"
	"log"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/robfig/cron/v3"
)

func StartCronJobs() {
	manilaTime, err := time.LoadLocation("Asia/Manila")
	if err != nil {
		log.Println("Error loading timezone, using local time")
		manilaTime = time.Local
	}

	c := cron.New(cron.WithLocation(manilaTime))

	c.AddFunc("0 0 * * *", func() {
		log.Println("Checking for due dates...")
		checkDueDates()

		log.Println("Checking for expired pickups...")
		checkExpiredPickups()
	})

	c.Start()
	log.Println("Automatic Scheduler Started")
}

func checkDueDates() {
	var activeBorrows []model.Transaction

	if err := database.DB.Where("status = ?", "Borrowed").Find(&activeBorrows).Error; err != nil {
		log.Println("Cron Error: Failed to fetch active borrows", err)
		return
	}

	now := time.Now()
	for _, tx := range activeBorrows {
		hoursLeft := tx.ReturnDate.Sub(now).Hours()
		daysLeft := int(hoursLeft / 24)

		var book model.Book
		title := tx.ISBN
		if err := database.DB.Where("isbn = ?", tx.ISBN).First(&book).Error; err == nil {
			title = book.Title
		}

		if daysLeft == 1 || (hoursLeft > 0 && hoursLeft <= 24) {
			msg := fmt.Sprintf("REMINDER: Your borrowed \"%s\" is due tomorrow. Please return it on time.",
				title)
			SendSystemNotification(tx.SchoolID, msg)

		} else if hoursLeft < 0 {
			msg := fmt.Sprintf("OVERDUE: Your borrowed \"%s\" is past its due date. Please return it immediately.",
				title)
			SendSystemNotification(tx.SchoolID, msg)
		}
	}
}

func checkExpiredPickups() {
	var expiredPickups []model.Transaction

	now := time.Now()

	if err := database.DB.Where("status = ? AND pickup_date < ?", "Approved", now).Find(&expiredPickups).Error; err != nil {
		log.Println("Cron Error: Failed to fetch expired pickups", err)
		return
	}

	for _, tx := range expiredPickups {
		if err := database.DB.Model(&tx).Update("status", "Rejected").Error; err != nil {
			log.Printf("Cron Error: Failed to reject transaction ID %d: %v\n", tx.ID, err)
			continue
		}

		history := model.TransactionHistory{
			TransactionID: tx.ID,
			SchoolID:      tx.SchoolID,
			ISBN:          tx.ISBN,
			Event:         "Reject",
			Staff:         "System",
			Date:          time.Now(),
		}
		if err := database.DB.Create(&history).Error; err != nil {
			log.Printf("Cron Error: Failed to create history for transaction ID %d: %v\n", tx.ID, err)
		}

		var book model.Book
		title := tx.ISBN
		if err := database.DB.Where("isbn = ?", tx.ISBN).First(&book).Error; err == nil {
			title = book.Title
		}

		msg := fmt.Sprintf("REJECTED: Your scheduled pickup for \"%s\" on %s was automatically rejected due to no-show. Please request again if still needed.",
			title,
			tx.PickupDate.Format("Jan 02, 2006 3:04 PM"),
		)
		SendSystemNotification(tx.SchoolID, msg)

		log.Printf("Auto-rejected transaction ID %d (SchoolID: %s) — pickup date passed.\n", tx.ID, tx.SchoolID)
	}
}

func SendSystemNotification(schoolID string, message string) {
	notif := &model.Notification{
		SchoolID: schoolID,
		Message:  message,
		IsRead:   false,
	}
	database.DB.Create(notif)

	payload := NotificationPayload{
		ID:   int64(notif.ID),
		Msg:  message,
		Time: time.Now().Format("Jan 02, 3:04 PM"),
		Read: false,
	}
	NotifHub.SendNotification(schoolID, payload)
}

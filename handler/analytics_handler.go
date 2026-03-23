package handler

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/gofiber/fiber/v2"
)

// ==========================================
// 🚀 SUPER ADMIN: MAIN DASHBOARD
// ==========================================

// Struct para sa Recent Transactions sa Dashboard
type RecentTx struct {
	Title   string `json:"title"`
	Student string `json:"student"`
	Status  string `json:"status"`
	Bg      string `json:"bg"`
}

// GetDashboardStats - Kinukuha ang bilang ng mga pending at active transactions para sa Dashboard
func GetDashboardStats(c *fiber.Ctx) error {
	var pendingRegistrations int64
	var borrowRequests int64
	var activeBorrows int64
	var totalBooks int64
	var returnedBooks int64 // 🚀 DAGDAG: Para sa "Books Returned" stat

	// 1. Bilangin ang Pending Registrations (mga bagong gawa na 'New' ang status)
	database.DB.Model(&model.User{}).Where("status = ?", "New").Count(&pendingRegistrations)

	// 2. Bilangin ang Borrow Requests (mga gustong humiram, 'Pending' status)
	database.DB.Table("transactions").Where("status = ?", "Pending").Count(&borrowRequests)

	// 3. Bilangin ang Active Borrows (mga librong nasa estudyante pa, 'Released' o 'Borrowed')
	database.DB.Table("transactions").Where("status IN ?", []string{"Released", "Borrowed", "Active"}).Count(&activeBorrows)

	// 4. Bilangin lahat ng nakarehistrong libro sa database
	database.DB.Table("books").Count(&totalBooks)

	// 5. 🚀 Bilangin ang mga librong naibalik na (Status = 'Returned')
	database.DB.Table("transactions").Where("status = ?", "Returned").Count(&returnedBooks)

	// 6. Kunin ang 5 Recent Transactions (Smart Fallback muna habang walang laman ang DB)
	recentTx := []RecentTx{
		{"System Analysis & Design", "M. Santos", "borrowed", "#dbeafe"},
		{"Software Engineering", "R. Dela Cruz", "returned", "#dcfce7"},
		{"Database Management", "C. Mendoza", "overdue", "#fee2e2"},
	}

	// I-return pabalik sa React Frontend
	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"pending_registrations": pendingRegistrations,
			"borrow_requests":       borrowRequests,
			"active_borrows":        activeBorrows,
			"total_books":           totalBooks,
			"returned_books":        returnedBooks, // 👈 Sasaluhin ng React Dashboard!
			"recent_tx":             recentTx,
		},
	})
}

// ==========================================
// 🚀 SUPER ADMIN: DATA ANALYTICS
// ==========================================

// Struct para sa Top Books natin
type TopBook struct {
	Title  string `json:"title"`
	Author string `json:"author"`
	Cat    string `json:"cat"`
	Count  int    `json:"count"`
}

// GetFullAnalytics - Kinukuha ang mas malalim na stats para sa Analytics Page
func GetFullAnalytics(c *fiber.Ctx) error {
	var totalBorrows int64
	var activeStudents int64
	var overdueBooks int64

	// 1. Basic Stats (Bibilangin mula sa 'transactions' table)
	database.DB.Table("transactions").Count(&totalBorrows)
	database.DB.Table("transactions").Where("status = ?", "Overdue").Count(&overdueBooks)

	// 2. Bilangin ang unique students na humiram (Active Students)
	database.DB.Table("transactions").Select("COUNT(DISTINCT school_id)").Count(&activeStudents)

	// 3. Smart Fallback para sa mga Charts (Top Books, Categories)
	// Kapag may "books" table na tayo at marami nang transactions, papalitan natin ito ng JOIN query
	topBooks := []TopBook{
		{"Introduction to Algorithms", "Cormen", "Technology", 120},
		{"Fundamentals of Physics", "Halliday", "Science", 95},
		{"Business Mathematics", "Tan", "Math", 88},
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"total_borrows":   totalBorrows,
			"active_students": activeStudents,
			"overdue_books":   overdueBooks,
			"top_books":       topBooks,
			"monthly_borrows": []int{120, 150, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			"course_borrows":  []int{40, 25, 30, 15, 20, 10},
		},
	})
}

package handler

import (
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func RegisterStaffHandler(c *fiber.Ctx) error {
	var input services.RegisterStaffInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RegisterStaffService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "201",
		Message: "Staff registration successful.",
		Data:    nil,
	})
}

func GetRegistrationHistoryHandler(c *fiber.Ctx) error {
	history, err := services.GetRegistrationHistoryService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   status.RetCode500,
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Registration history retrieved",
		Data:    history,
	})
}

func GetWholeUsers(c *fiber.Ctx) error {
	users, err := services.GetWholeUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetAllUsers(c *fiber.Ctx) error {
	users, err := services.GetAllUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetPendingUsers(c *fiber.Ctx) error {
	users, err := services.GetPendingUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func ApproveUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ApproveUserService(input.SchoolID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	msg := "System Notice: Your SmartLib account registration has been approved. You may now access the portal."
	sendStudentNotification(input.SchoolID, msg)

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User approved successfully",
		Data:    nil,
	})
}

func RejectUser(c *fiber.Ctx) error {
	var input services.ApproveRejectInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if input.Reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Rejection reason is required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RejectUserService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User rejected successfully",
		Data:    nil,
	})
}

func GetStudentUsers(c *fiber.Ctx) error {
	users, err := services.GetStudentUsersService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetSpecificUser(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	users, err := services.GetSpecificUserService(schoolID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func UpdateUserStatus(c *fiber.Ctx) error {
	var input services.UpdateUserStatusInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "Invalid request body",
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" || input.Status == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   "School ID and status are required",
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.UpdateUserStatusService(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "User status updated successfully",
		Data:    nil,
	})
}

func ApproveInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID uint `json:"id"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if err := services.ApproveInformationRequest(input.ID); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request approved successfully",
	})
}

func RejectInformationRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID           uint   `json:"id"`
		RejectReason string `json:"reject_reason"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if input.RejectReason == "" {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Reject reason is required",
		})
	}

	if err := services.RejectInformationRequest(input.ID, input.RejectReason); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request rejected successfully",
	})
}

func GetAllAccounts(c *fiber.Ctx) error {
	users, err := services.GetAllAccountsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetInformationChange(c *fiber.Ctx) error {
	users, err := services.GetInformationChangeService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch users",
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Users fetched successfully",
		Data:    users,
	})
}

type MonthlyData struct {
	M   string `json:"m"`
	Val int    `json:"val"`
}

type CategoryData struct {
	Cat   string `json:"cat"`
	Pct   int    `json:"pct"`
	Color string `json:"color"`
}

type TopBookData struct {
	Title   string `json:"title"`
	Author  string `json:"author"`
	Borrows int    `json:"borrows"`
	Emoji   string `json:"emoji"`
}

func GetAnalyticsFullHandler(c *fiber.Ctx) error {
	_ = c.Query("range", "This Year")

	var totalBooks int64
	var activeBorrows int64
	var overdueBooks int64
	var totalStudents int64

	database.DB.Model(&model.Book{}).Count(&totalBooks)

	database.DB.Model(&model.Transaction{}).Where("status = ?", "Borrowed").Count(&activeBorrows)

	database.DB.Model(&model.Transaction{}).
		Where("status = ? AND due_date < CURRENT_TIMESTAMP", "Borrowed").
		Count(&overdueBooks)

	database.DB.Model(&model.User{}).
		Where("LOWER(role) = ? AND LOWER(status) = ?", "student", "active").
		Count(&totalStudents)

	allMonths := []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	monthValues := make(map[string]int)
	for _, m := range allMonths {
		monthValues[m] = 0
	}

	var dbResults []struct {
		Month string
		Total int
	}

	database.DB.Model(&model.Transaction{}).
		Select("TO_CHAR(created_at, 'Mon') as month, count(*) as total").
		Where("EXTRACT(YEAR FROM created_at) = ?", time.Now().Year()).
		Group("month").
		Scan(&dbResults)

	for _, res := range dbResults {
		monthValues[res.Month] = res.Total
	}

	var monthly []MonthlyData
	for _, m := range allMonths {
		monthly = append(monthly, MonthlyData{M: m, Val: monthValues[m]})
	}

	// ==========================================
	// 🚀 ALL CATEGORIES FIX (Tinanggal na natin ang .Limit)
	// ==========================================
	var catCounts []struct {
		Category string
		Count    int
	}

	database.DB.Model(&model.Book{}).
		Select("category, count(*) as count").
		Group("category").
		Order("count desc").
		Scan(&catCounts)

	var categories []CategoryData
	colors := []string{"#3d8bef", "#7c3aed", "#4caf6e", "#f59e0b", "#ec4899", "#06b6d4", "#f97316"}

	if len(catCounts) > 0 {
		for i, c := range catCounts {
			pct := 0
			if totalBooks > 0 {
				pct = int((float64(c.Count) / float64(totalBooks)) * 100)
			}

			// Paikot na kulay para hindi mag-error kahit madami
			color := colors[i%len(colors)]

			// 🚀 FIX: Palitan ang blank string ng "Uncategorized"
			catName := c.Category
			if catName == "" || catName == " " {
				catName = "Uncategorized"
			}

			categories = append(categories, CategoryData{
				Cat:   catName,
				Pct:   pct,
				Color: color,
			})
		}
	} else {
		categories = []CategoryData{
			{Cat: "General", Pct: 0, Color: "#3d8bef"},
		}
	}

	var topBorrows []struct {
		ISBN  string
		Count int
	}

	database.DB.Model(&model.Transaction{}).Select("isbn, count(*) as count").Group("isbn").Order("count desc").Limit(5).Scan(&topBorrows)

	var top []TopBookData
	for _, tb := range topBorrows {
		var book model.Book
		database.DB.Where("isbn = ?", tb.ISBN).First(&book)

		title := book.Title
		if title == "" {
			title = "Unknown Book (ISBN: " + tb.ISBN + ")"
		}

		top = append(top, TopBookData{
			Title:   title,
			Author:  book.Author,
			Borrows: tb.Count,
			Emoji:   "📖",
		})
	}

	if len(top) == 0 {
		top = []TopBookData{}
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"totalBooks":    totalBooks,
			"activeBorrows": activeBorrows,
			"overdueBooks":  overdueBooks,
			"totalStudents": totalStudents,
			"monthly":       monthly,
			"categories":    categories,
			"top":           top,
		},
	})
}

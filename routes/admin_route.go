package routes

import (
	"SmartLib_Likod/handler"
	"SmartLib_Likod/middleware"

	"github.com/gofiber/fiber/v2"
)

func SetupAdminRoutes(api fiber.Router) {
	admin := api.Group("/admin", middleware.AuthMiddleware)
	admin.Get("/school", handler.GetSchool)
	admin.Post("/program", handler.CreateProgramHandler)
	admin.Put("/program/:id", handler.UpdateProgramHandler)
	admin.Delete("/program/:id", handler.DeleteProgramHandler)
	admin.Get("/wholeUsers", handler.GetWholeUsers)
	admin.Get("/allUsers", handler.GetAllUsers)
	admin.Get("/pendingUsers", handler.GetPendingUsers)
	admin.Get("/archivedStudents", handler.GetArchivedStudents)
	admin.Get("/archivedUsers", handler.GetArchivedUsers)
	admin.Get("/studentUsers", handler.GetStudentUsers)
	admin.Get("/specificUser/:school_id", handler.GetSpecificUser)
	admin.Put("/status", handler.UpdateUserStatus)
	admin.Get("/signin-history", handler.GetSigninHistory)

	admin.Put("/approve", handler.ApproveUser)
	admin.Put("/reject", handler.RejectUser)

	admin.Get("/all", handler.GetAllAccounts)
	admin.Post("/addStaff", handler.RegisterStaffHandler)

	admin.Get("/informationChange", handler.GetInformationChange)
	admin.Put("/approveInformationChange", handler.ApproveInformationRequestHandler)
	admin.Put("/rejectInformationChange", handler.RejectInformationRequestHandler)
}

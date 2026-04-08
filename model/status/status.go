package status

const (
	// API response
	RetCode400 = "Bad Request"
	RetCode401 = "Unauthorized"
	RetCode404 = "Not Found"
	RetCode419 = "Authentication Timeout"
	RetCode500 = "Internal Server Error"

	// User status
	UserStatusPending = "Pending"
	UserStatusActive  = "Active"
	UserStatusLocked  = "Locked"

	RoleStudent = "Student"
	RoleStaff   = "Staff"
	RoleAdmin   = "Admin"
)

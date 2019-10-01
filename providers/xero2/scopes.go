package xero2

// Define scopes supported by Xero.
// See: https://developer.xero.com/documentation/oauth2/scopes
const (
	// To get a refresh token, you must request the offline_access scope.
	// A refresh token allows you to refresh your access token and maintain an offline connection.
	ScopeOfflineAccess = "offline_access"

	// OpenID scopes.
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"

	// Accounting scopes.
	ScopeAccountingTransactions     = "accounting.transactions"
	ScopeAccountingTransactionsRead = "accounting.transactions.read"
	ScopeAccountingReportsRead      = "accounting.reports.read"
	ScopeAccountingJournalsRead     = "accounting.journals.read"
	ScopeAccountingSettings         = "accounting.settings"
	ScopeAccountingSettingsRead     = "accounting.settings.read"
	ScopeAccountingContacts         = "accounting.contacts"
	ScopeAccountingContactsRead     = "accounting.contacts.read"
	ScopeAccountingAttachments      = "accounting.attachments"
	ScopeAccountingAttachmentsRead  = "accounting.attachments"
)

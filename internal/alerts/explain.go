package alerts

import "errors"

// explained are the sentences a page shows for each refusal. None of them
// repeats what a server said, an address with a token, or a password.
var explained = []struct {
	err  error
	text string
}{
	{ErrTelegramToken, "Telegram does not accept this bot token. Copy it again from @BotFather."},
	{ErrTelegramChat, "The bot cannot write to this chat. Send the bot a message first, or add it to the group, then check the chat ID."},
	{ErrTelegramUnreachable, "Rootwell could not reach Telegram. This server needs to reach api.telegram.org on port 443."},
	{ErrTelegramRefused, "Telegram did not take the message. Try again in a while."},
	{ErrEmailSettings, "Fill in the mail server, its port, the sender and at least one recipient. A password needs a user name."},
	{ErrEmailAddress, "Rootwell does not send mail to this machine itself, link-local or reserved addresses. Use the mail server's own name or address."},
	{ErrEmailUnreachable, "Rootwell could not reach the mail server. Check its name and port, and that this server may reach it."},
	{ErrEmailTLS, "The mail server's TLS could not be checked. It needs STARTTLS or TLS, and a certificate from a public authority or one saved in Certificates."},
	{ErrEmailSignIn, "The mail server did not accept the user name and password."},
	{ErrEmailRefused, "The mail server did not take the message. Check the sender and the recipients."},
}

// Explain gives the sentence a page shows for err.
func Explain(err error) string {
	for _, e := range explained {
		if errors.Is(err, e.err) {
			return e.text
		}
	}
	return "The alert could not be sent. Try again in a while."
}

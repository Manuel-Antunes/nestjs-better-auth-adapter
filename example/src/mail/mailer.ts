export interface MailMessage {
	to: string;
	subject: string;
	text: string;
	html?: string;
}

/**
 * How the app sends email. An abstract class rather than an interface, so it
 * is its own injection token: `SmtpMailer` in the app, an in-memory outbox in
 * the e2e suites (`overrideProvider(Mailer)`).
 */
export abstract class Mailer {
	abstract send(message: MailMessage): Promise<void>;
}

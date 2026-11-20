import { Injectable } from "@nestjs/common";
import { type MailMessage, Mailer } from "../../src/mail/mailer.ts";

/** Keeps every email in an outbox, for the suites to read links from. */
@Injectable()
export class InMemoryMailer extends Mailer {
	readonly outbox: MailMessage[] = [];

	async send(message: MailMessage) {
		this.outbox.push(message);
	}

	/** The last email sent to `to` whose subject matches, or a failed test. */
	last(to: string, subject: RegExp): MailMessage {
		const message = this.outbox
			.filter((mail) => mail.to === to && subject.test(mail.subject))
			.at(-1);
		if (!message) {
			throw new Error(
				`No email to ${to} matching ${subject}. Sent: ${this.outbox
					.map((mail) => `${mail.to}: ${mail.subject}`)
					.join(", ")}`,
			);
		}
		return message;
	}

	/** The first link in the last matching email. */
	link(to: string, subject: RegExp): string {
		const url = /https?:\/\/\S+/.exec(this.last(to, subject).text)?.[0];
		if (!url) throw new Error(`No link in the email to ${to}`);
		return url;
	}
}

import { Injectable, Logger, type OnModuleDestroy } from "@nestjs/common";
import { InjectEnv } from "../config/config.module.ts";
import nodemailer, { type Transporter } from "nodemailer";
import type { Env } from "../config/env.ts";
import { type MailMessage, Mailer } from "./mailer.ts";

/** Sends through SMTP: Mailpit locally (`docker compose up`), your provider in production. */
@Injectable()
export class SmtpMailer extends Mailer implements OnModuleDestroy {
	private readonly logger = new Logger(SmtpMailer.name);
	private readonly transport: Transporter;
	private readonly from: string;

	constructor(@InjectEnv() env: Env) {
		super();
		this.transport = nodemailer.createTransport(env.SMTP_URL);
		this.from = env.MAIL_FROM;
	}

	async send(message: MailMessage) {
		await this.transport.sendMail({ from: this.from, ...message });
		this.logger.debug(`Sent "${message.subject}" to ${message.to}`);
	}

	onModuleDestroy() {
		this.transport.close();
	}
}

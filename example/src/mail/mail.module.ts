import { Global, Injectable, Module } from "@nestjs/common";
import { InjectEnv } from "../config/config.module.ts";
import { OnEvent } from "@nestjs/event-emitter";
import { AppEvent } from "../common/enums/app-event.enum.ts";
import { type UserEvent } from "../common/events.ts";
import type { Env } from "../config/env.ts";
import { Mailer } from "./mailer.ts";
import { SmtpMailer } from "./smtp.mailer.ts";
import { templates } from "./templates.ts";

/** Lifecycle emails, sent when the domain events say so. */
@Injectable()
export class LifecycleMails {
	private readonly appName: string;

	constructor(
		private readonly mailer: Mailer,
		@InjectEnv() env: Env,
	) {
		this.appName = env.APP_NAME;
	}

	@OnEvent(AppEvent.UserRegistered, { async: true, suppressErrors: true })
	welcome(event: UserEvent) {
		return this.mailer.send({
			to: event.email,
			...templates.welcome(this.appName, event.name),
		});
	}

	@OnEvent(AppEvent.UserDeleted, { async: true, suppressErrors: true })
	goodbye(event: UserEvent) {
		return this.mailer.send({
			to: event.email,
			...templates.goodbye(this.appName, event.name),
		});
	}
}

@Global()
@Module({
	providers: [{ provide: Mailer, useClass: SmtpMailer }, LifecycleMails],
	exports: [Mailer],
})
export class MailModule {}

import { Global, Module } from "@nestjs/common";
import { ClsModule } from "nestjs-cls";
import { requestContextOptions } from "./request-context.ts";

@Global()
@Module({
	imports: [
		// Opens the request context for the app's own routes; modules inject
		// `RequestMetadata` with `ClsModule.forFeature(RequestMetadata)`.
		ClsModule.forRoot({
			global: true,
			middleware: { mount: true, ...requestContextOptions },
		}),
	],
})
export class CommonModule {}

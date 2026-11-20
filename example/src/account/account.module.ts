import { Module } from "@nestjs/common";
import { AccountController } from "./account.controller.ts";

@Module({ controllers: [AccountController] })
export class AccountModule {}

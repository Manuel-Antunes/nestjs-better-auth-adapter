import { Module } from "@nestjs/common";
import { MetaController } from "./meta.controller.ts";

@Module({ controllers: [MetaController] })
export class MetaModule {}

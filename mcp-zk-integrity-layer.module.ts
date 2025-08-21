import { Module } from '@nestjs/common';
import { McpZkIntegrityLayerService } from './mcp-zk-integrity-layer.service';
import { EvmUtils } from 'modules/blockchain/evm.utils';
import { KmsModule } from 'modules/kms/kms.module';
import { DatabaseModule } from 'modules/database/database.module';
import { SettingsModule } from 'modules/settings/settings.module';

@Module({
    imports: [
        KmsModule,
        DatabaseModule,
        SettingsModule
    ],
    providers: [
        McpZkIntegrityLayerService,
        EvmUtils
    ],
    exports: [McpZkIntegrityLayerService]
})
export class McpZkIntegrityLayerModule {}
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppContext } from './app.context';
import { DashboardService } from './dashboard.service';
import { NetworkService } from './network.service';
import { StateService } from './state.service';
import { StatusService } from './status.service';
import { SystemService } from './system.service';

@Module({
  controllers: [AppController],
  providers: [AppContext, DashboardService, NetworkService, StateService, StatusService, SystemService],
})
export class AppModule {}

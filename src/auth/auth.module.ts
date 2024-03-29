import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JWTStrategy } from './strategy.service';

@Module({
  controllers: [AuthController],
  providers: [AuthService, JWTStrategy],
  imports: [JwtModule.register({})],
})
export class AuthModule {}

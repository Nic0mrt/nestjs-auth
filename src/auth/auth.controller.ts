import { Body, Controller, Delete, Post, Req, UseGuards } from '@nestjs/common';
import { SignupDTO } from './dto/singup.dto';
import { SigninDTO } from './dto/signin.dto';
import { AuthService } from './auth.service';
import { ResetPasswordDTO } from './dto/resetPassword.dto';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signUp(@Body() signupDTO: SignupDTO) {
    return this.authService.signUp(signupDTO);
  }

  @Post('signin')
  signIn(@Body() signinDTO: SigninDTO) {
    return this.authService.signIn(signinDTO);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPasswordDTO: ResetPasswordDTO) {
    return this.authService.resetPassword(resetPasswordDTO);
  }
  @UseGuards(AuthGuard('jwt'))
  @Delete('delete-account')
  deleteAccount(@Req() req: Request) {
    console.log(typeof req.user['id']);
    return this.authService.deleteAccount({ id: req.user['id'] });
  }
}

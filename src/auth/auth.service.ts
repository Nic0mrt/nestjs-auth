import {
  ConflictException,
  Injectable,
  NotFoundException,
  Req,
} from '@nestjs/common';
import { SignupDTO } from './dto/singup.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as brcrypt from 'bcrypt';
import { SigninDTO } from './dto/signin.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDTO } from './dto/resetPassword.dto';
import { Request } from 'express';
import { DeleteAccountDTO } from './dto/deleteAccount.dto';
import { SlowBuffer } from 'buffer';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signIn(signinDTO: SigninDTO) {
    const { email, password } = signinDTO;
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new NotFoundException('Invalid credentials');
    }
    const isMatch = await brcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new NotFoundException('Invalid credentials');
    }
    const payload = { email: user.email, sub: user.id };
    const token = await this.jwtService.sign(payload, {
      expiresIn: '1d',
      secret: this.configService.get('JWT_SECRET'),
    });
    return { data: { email: user.email, id: user.id, token } };
  }

  async signUp(signupDTO: SignupDTO) {
    const { email, password } = signupDTO;
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (user) {
      throw new ConflictException('User already exists');
    }
    const hash = await brcrypt.hash(password, 10);
    const newUser = await this.prismaService.user.create({
      data: { email, password: hash },
    });

    return { data: { email: newUser.email, id: newUser.id } };
  }

  async resetPassword(resetPasswordDTO: ResetPasswordDTO) {
    const { email, password, newPassword } = resetPasswordDTO;
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new NotFoundException('Invalid credentials');
    }
    const isMatch = await brcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new NotFoundException('Invalid credentials');
    }

    const hash = await brcrypt.hash(newPassword, 10);
    await this.prismaService.user.update({
      where: { email },
      data: { password: hash },
    });
    return {
      data: { email: user.email, id: user.id },
      message: 'Password updated successfully',
    };
  }

  async deleteAccount(deleteAccountDTO: DeleteAccountDTO) {
    const { id } = deleteAccountDTO;
    await this.prismaService.user.delete({
      where: { id },
    });
    return { message: 'Account deleted successfully' };
  }
}

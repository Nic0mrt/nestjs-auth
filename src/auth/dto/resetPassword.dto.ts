import { IsEmail, IsNotEmpty } from 'class-validator';

export class ResetPasswordDTO {
  @IsNotEmpty()
  readonly password: string;

  @IsNotEmpty()
  @IsEmail()
  readonly email: string;

  @IsNotEmpty()
  readonly newPassword: string;
}

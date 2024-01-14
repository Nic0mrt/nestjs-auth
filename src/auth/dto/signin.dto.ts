import { IsEmail, IsNotEmpty } from 'class-validator';

export class SigninDTO {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsNotEmpty()
  password: string;
}

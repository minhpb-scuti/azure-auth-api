// auth.service.ts
import { ConflictException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcrypt';
import { AuthCredentialsDto } from './dto/auth-credentials.dto/auth-credentials.dto';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, password: string): Promise<any> {
    const user = await this.userService.findUserByUsername(username);
    if (user && bcrypt.compareSync(password, user.password)) {
      return user;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto;

    // Kiểm tra xem người dùng đã tồn tại trong cơ sở dữ liệu chưa
    const existingUser = await this.userService.findUserByUsername(username);
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }

    // Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
    const saltRounds = 10; // Độ dài salt
    const hashedPassword = bcrypt.hashSync(password, saltRounds);

    // Tạo một đối tượng người dùng mới và lưu vào cơ sở dữ liệu
    const newUser = await this.userService.createUser(username, hashedPassword);
    console.log('newUser', newUser);

    // Có thể thực hiện các xử lý bổ sung khác sau khi đăng ký thành công
  }
}

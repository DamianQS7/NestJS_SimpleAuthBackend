import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response.interface';
import { RegisterUserDto, UpdateAuthDto, LoginDto, CreateUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {

  constructor(private readonly authService: AuthService) {}

  @Post()
  public create(@Body() createUserDto: CreateUserDto): Promise<User> {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  public login(@Body() loginDto: LoginDto): Promise<LoginResponse> {
    return this.authService.login(loginDto);
  }

  @Post('/register')
  public register(@Body() registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    return this.authService.register(registerUserDto);
  }

  @Get()
  @UseGuards(AuthGuard)
  public findAll(@Request() req: Request): Promise<User[]> {
    return this.authService.findAll();
  }

  @UseGuards(AuthGuard)
  @Get('/check-token')
  public checkToken(@Request() req: Request): LoginResponse {
    const user = req['user'] as User;

    return {
      user,
      token: this.authService.getJwtToken({id: user._id})
    }
  }

  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
  
}

import { 
  BadRequestException, 
  Injectable, 
  InternalServerErrorException, 
  UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';

import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';


import { User } from './entities/user.entity';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { CreateUserDto, RegisterUserDto, LoginDto, UpdateAuthDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,

    private jwtService: JwtService
  ) {}

  public async create(createUserDto: CreateUserDto): Promise<User> {
    try {

      const {password, ...userData} = createUserDto;
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const {password: _, ...user} = newUser.toJSON();

      return user;

    } catch (error) {

      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists.`);
      }

      throw new InternalServerErrorException('Something went wrong with this request');
    }
  }

  public async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create(registerUserDto);

    return {
      user: user,
      token: this.getJwtToken({id: user._id})
    }
  }

  public async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({email});

    if (!user) throw new UnauthorizedException('Email not found');

    if ( !bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Incorrect Password')
    }

    const { password: _, ...userMinusPassword } = user.toJSON();

    return { 
      user: userMinusPassword, 
      token: this.getJwtToken({ id: user.id })
    }
  }

  public findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  public async findUserById(id: string): Promise<User> {
    const userDoc = await this.userModel.findById(id);
    const { password, ...user} = userDoc.toJSON();
    return user;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  public getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}

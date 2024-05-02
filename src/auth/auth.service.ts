import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bycrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interfaces';
import { RegisterDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {

  constructor( 
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
   
    
    try{
      
      const { password, ...userData } = createUserDto;
      
      
      const newUser = new this.userModel({
        password: bycrypt.hashSync(password, 10),
        ...userData
      });

      await newUser.save();

      const  { password:_, ...user} = newUser.toJSON();

      return user
    }catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email } already exists`);
      }
      throw new InternalServerErrorException('Something went wrong!');
    }

  }

  async register(registerDto: RegisterDto): Promise<LoginResponse> {

    try{
      
      const { password, ...userData } = registerDto;
      
      
      const newUser = new this.userModel({
        password: bycrypt.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const user = await this.userModel.findOne({ email:registerDto.email });

      const  { password:_, ...rest} = newUser.toJSON();

      return{
        user: user,
        token: await this.getJwtToken({ id: user.id })
      }

    }catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${ registerDto.email } already exists`);
      }
      throw new InternalServerErrorException('Something went wrong!');
    }



  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password  } = loginDto

    const user = await this.userModel.findOne({ email });


    if(!user){
      throw new UnauthorizedException('Not valid credentials - email');
    }
    
    if(!bycrypt.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials - passwrod');
    }

    const { password: _, ...rest } = user.toJSON()

    return {
      user: rest,
      token: await this.getJwtToken({ id: user.id })
    }
  }

  findAll() {
    return `This action returns all auth`;
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

  getJwtToken(payload: JwtPayload) {

    return this.jwtService.sign( payload );
    
  }
}

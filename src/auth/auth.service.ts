import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, RegisterDto, LoginDto, UpdateAuthDto } from './dto';
import { LoginResponse } from './interfaces/login-response.interfaces';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bycrypt from 'bcryptjs';

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

    const user = await this.create(registerDto)
    
    return{
      user,
      token: await this.getJwtToken({ id: user._id }),
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

  findAll(): Promise<User[]> {
    return this.userModel.find();
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

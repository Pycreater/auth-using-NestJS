import { Body, Controller, Post, HttpStatus, HttpException, BadRequestException, Res, Get, Req, UnauthorizedException } from '@nestjs/common';
import { AppService } from './app.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';

@Controller('api')
export class AppController {
  constructor(private readonly appService: AppService,
    private jwtService: JwtService
  ) {}

  @Post('register')
  async register(
    @Body('name') name: string,
    @Body('email') email: string,
    @Body('password') password: string,
  ) {
    try {
      // Hashing the password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Create user using the AppService
      const newUser = await this.appService.create({
        name,
        email,
        password: hashedPassword,
      });
      
      delete newUser.password;

      // Return a success response
      return {
        statusCode: HttpStatus.CREATED,
        message: 'User registered successfully',
        user: newUser,
      };
    } catch (error) {
      // Handle errors gracefully
      throw new HttpException('Failed to register user', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('login')
  async login(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({passthrough: true}) res: Response
  ) {
    const user = await this.appService.findOne(email);

    if(!user) {
      throw new BadRequestException("Invalid Credentials!");
    }

    
    if(!await bcrypt.compare(password, user.password)) {
      throw new BadRequestException("Invalid Credentials!"); 
    }

    const jwt = await this.jwtService.signAsync({id: user.id});
    res.cookie('jwt', jwt, {httpOnly: true});

    return {
      msg: "Success",
    };
    
  }

  @Get('user')
async user(@Req() req: Request){
  try{
    const cookie = req.cookies['jwt'];
    console.log('JWT Cookie:', cookie); // Log the JWT cookie value for debugging

    const data = await this.jwtService.verifyAsync(cookie);
    console.log('Decoded JWT Data:', data); // Log decoded JWT data for debugging

    if(!data || !data['id']) {
      throw new UnauthorizedException('Invalid JWT token or missing user ID');
    }

    const user = await this.appService.findOne(data['email']);
    console.log('Retrieved User:', user); // Log the user object retrieved from findOne

    if (!user) {
      throw new UnauthorizedException('User not found');
    }


     const {password, ...result} = user; 

    return result;
  } catch (e) {
    throw new UnauthorizedException('Failed to retrieve user data');
  }
}

@Post()
async logout(@Res({passthrough: true}) res: Response) {
  res.clearCookie('jwt');

  return{
    message: "success"
  }
}

}

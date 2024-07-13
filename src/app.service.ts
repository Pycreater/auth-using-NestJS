import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entity/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AppService {
  
  constructor(@InjectRepository(User) private readonly userRepository: Repository<User>) {}

  async create(data: any): Promise<User> {
      return this.userRepository.save(data);
  }

  async findOne(email: string): Promise<User> {
    return this.userRepository.findOne({ where: {email}});
  }
}

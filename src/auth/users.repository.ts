import { ConflictException } from '@nestjs/common';
import { EntityRepository, Repository } from 'typeorm';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { User } from './user.entity';
import * as bcrypy from 'bcrypt';

@EntityRepository(User)
export class UsersRepository extends Repository<User> {
  async createUser(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    const { username, password } = authCredentialsDto;
    const salt = await bcrypy.genSalt();
    const hashedPassword = await bcrypy.hash(password, salt);
    const user = this.create({
      username: username,
      password: hashedPassword,
    });
    try {
      await this.save(user);
    } catch (error) {
      if (error.errno === 19) {
        // 19 is duplicate error code for sqlite
        throw new ConflictException('Username already exists');
      }
    }
  }
}

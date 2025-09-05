import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { Injectable, UnauthorizedException } from '@nestjs/common';

import { AuthService } from '../auth.service';
import { JwtUserPayloadDto } from '../dto/jwt-user-payload.dto';
import { User } from '../../../entities/user.entity';
import { AccessUnauthorizedException } from '../../../exceptions/access-exceptions';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string): Promise<JwtUserPayloadDto> {
    let user: User;
    try {
      user = await this.authService.validateUser(email, password);
    } catch (e) {
      throw new AccessUnauthorizedException(JSON.stringify(e));
    }

    if (!user) {
      throw new AccessUnauthorizedException();
    }

    return { _id: String(user.id) };
  }
}

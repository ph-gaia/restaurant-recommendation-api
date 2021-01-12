import { Controller, Post, Get, Middleware, Put } from '@overnightjs/core';
import { Response, Request } from 'express';
import { User } from '@src/models/user';
import AuthService from '@src/services/auth';
import { BaseController } from './index';
import { authMiddleware } from '@src/middlewares/auth';

@Controller('users')
export class UsersController extends BaseController {
  @Post('')
  public async create(req: Request, res: Response): Promise<void> {
    try {
      const user = new User(req.body);
      const newUser = await user.save();
      res.status(201).send(newUser);
    } catch (error) {
      this.sendCreateUpdateErrorResponse(res, error);
    }
  }

  @Post('authenticate')
  public async authenticate(req: Request, res: Response): Promise<Response> {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return this.sendErrorResponse(res, {
        code: 401,
        message: 'User not found!',
        description: 'Try verifying your email address.',
      });
    }
    if (
      !(await AuthService.comparePasswords(req.body.password, user.password))
    ) {
      return this.sendErrorResponse(res, {
        code: 401,
        message: 'Password does not match!',
      });
    }
    const token = AuthService.generateToken(user.toJSON());

    return res.send({ ...user.toJSON(), ...{ token } });
  }

  @Get('')
  public async list(req: Request, res: Response): Promise<Response> {
    const user = await User.find({});
    if (!user) {
      return this.sendErrorResponse(res, {
        code: 404,
        message: 'No registered users!',
      });
    }

    return res.send({ user });
  }

  @Put(':id')
  public async update(req: Request, res: Response): Promise<Response> {
    const user = await User.findOneAndUpdate(
      { _id: req.params.id }, req.body
    );

    if (!user) {
      return this.sendErrorResponse(res, {
        code: 404,
        message: 'User not found!',
      });
    }

    return res.send({ user });
  }

  @Get('me')
  @Middleware(authMiddleware)
  public async me(req: Request, res: Response): Promise<Response> {
    const email = req.decoded ? req.decoded.email : undefined;
    const user = await User.findOne({ email });
    if (!user) {
      return this.sendErrorResponse(res, {
        code: 404,
        message: 'User not found!',
      });
    }

    return res.send({ user });
  }
}

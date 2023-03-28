import { authenticate, AuthenticationBindings } from '@loopback/authentication';
import { authorize } from '@loopback/authorization';
import { inject } from '@loopback/core';
import { Count, CountSchema, Filter, repository, Where } from '@loopback/repository';
import {
  del,
  get,
  getFilterSchemaFor,
  getJsonSchemaRef,
  getModelSchemaRef,
  getWhereSchemaFor,
  HttpErrors,
  param,
  post,
  put,
  requestBody,
} from '@loopback/rest';
import { securityId, UserProfile } from '@loopback/security';
import * as _ from 'lodash';

import { generateOTP } from '../helpers';
import { PasswordHasherBindings, TokenServiceBindings, UserServiceBindings } from '../keys';
import { User } from "../models";	
import { Credentials, DisconnectedRepository, EmployerRepository, LaborRepository, LocationRequestRepository, OtpRepository, UserRepository, ViewerRepository } from '../repositories';
import { authorizeUser } from '../services/authorizeUser';
import { EmailService } from '../services/email.service';
import { BcryptHasher } from '../services/hash.password.bcrypt';
import { JWTService } from '../services/jwt-service';
import { MyUserService } from '../services/user.service';
import { validateCredentials } from '../services/validator';

export class UserController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    @repository(EmployerRepository)
    public employerRepository: EmployerRepository,
    @repository(LaborRepository)
    public laborRepository: LaborRepository,
    @repository(DisconnectedRepository)
    public disconnectedRepository: DisconnectedRepository,
    @repository(LocationRequestRepository)	
    public locationRepository: LocationRequestRepository,
    @repository(ViewerRepository)
    public viewerRepository: ViewerRepository,
    @repository(OtpRepository)
    public otpRepository: OtpRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public hasher: BcryptHasher,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
    @inject('services.EmailService')
    private emailService: EmailService,
  ) {}

  @post('/users/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async signup(
    @requestBody({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            title: 'User registeration',
            properties: {
              location: {type: 'string'},
              phone: {type: 'string'},
              skills: {type: 'array'},
              name: {type: 'string'},
              email: {type: 'string'},
              username: {type: 'string'},
              password: {type: 'string'},
              lat: { type: "number" },	
              lng: { type: "number" },
            },
            required: [
              'email',
              'password',
              'location',
              'phone',
              'name',
              'username',
              "lat",	
              "lng",
            ],
          },
        },
      },
    })
    userData: User & {
      location: string;
      phone: string;
      skills: Array<object>;
      lat: number;	
      lng: number;
    },
  ) {
    validateCredentials(_.pick(userData, ['email', 'password']));
    userData.role = userData.skills ? ['labor'] : ['employer'];
    userData.password = await this.hasher.hashPassword(userData.password);

    const newUser = await this.userRepository.create( _.omit(userData, ["skills", "location", "phone", "lat", "lng"]));

    if (userData.skills) {
      await this.laborRepository.create({
        userId: newUser.id,
        skills: userData.skills,
        location: userData.location,
        phone: userData.phone,
        lat: userData.lat,	
        lng: userData.lng,
      });
    } else {
      await this.employerRepository.create({
        userId: newUser.id,
        location: userData.location,
        phone: userData.phone,
        lat: userData.lat,	
        lng: userData.lng,
      });
    }

    return _.omit(newUser, 'password');
  }

  @post('/users/verify-otp', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async verifyOTP(
    @requestBody({
      description: 'The Input otp verification',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['otp'],
            properties: {
              otp: {
                type: 'string',
                maxLength: 6,
              },
            },
          },
        },
      },
    })
    request: {
      otp: string;
    },
  ): Promise<{token: string}> {
    const otp = await this.otpRepository.findOne({
      where: {
        otp: request.otp,
      },
    });
    if (!otp) {
      throw new HttpErrors.NotFound(`user not found with this otp`);
    }
    const user = await this.userRepository.findById(otp?.userId);
    const userProfile = this.userService.convertToUserProfile(user);
    userProfile.role = user.role;
    userProfile.id = user.id;
    const jwt = await this.jwtService.generateToken(userProfile);
    await this.otpRepository.deleteAll({userId: otp.userId});
    return Promise.resolve({token: jwt});
  }

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody({
      description: 'The Input of login function',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['email', 'password'],
            properties: {
              email: {
                type: 'string',
                format: 'email',
              },
              password: {
                type: 'string',
                minLength: 8,
              },
            },
          },
        },
      },
    })
    credentials: Credentials,
  ): Promise<{message: string}> {
    const user = await this.userService.verifyCredentials(credentials);
    const userProfile = this.userService.convertToUserProfile(user);
    const otp = generateOTP(Number(userProfile[securityId]));
    await this.otpRepository.deleteAll({
      userId: Number(userProfile[securityId]),
      type: "LOGIN",
    });
    await this.otpRepository.create({
      userId: Number(userProfile[securityId]),
      otp: otp,
      type: "LOGIN",	
      data: {},
    });
    await this.emailService.sendEmail(
      credentials.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for verifying your account on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the login process.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );
    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
    };
  }

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['admin'],
    voters: [authorizeUser],
  })
  @get('/users/count', {
    responses: {
      '200': {
        description: 'User model count',
        content: {'application/json': {schema: CountSchema}},
      },
    },
  })
  async count(
    @param.query.object('where', getWhereSchemaFor(User)) where?: Where<User>,
  ): Promise<Count> {
    return this.userRepository.count(where);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @get('/users', {
    responses: {
      '200': {
        description: 'Array of User model instances',
        content: {
          'application/json': {
            schema: {
              type: 'array',
              items: getModelSchemaRef(User, {includeRelations: true}),
            },
          },
        },
      },
    },
  })
  async find(
    @param.query.object('filter', getFilterSchemaFor(User))
    filter?: Filter<User>,
  ): Promise<User[]> {
    return this.userRepository.find(filter);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @get('/users/{id}', {
    responses: {
      '200': {
        description: 'User model instance',
        content: {
          'application/json': {
            schema: getModelSchemaRef(User, {includeRelations: true}),
          },
        },
      },
    },
  })
  async findById(
    @param.path.number('id') id: number,
    @param.query.object('filter', getFilterSchemaFor(User))
    filter?: Filter<User>,
  ): Promise<User> {
    return this.userRepository.findById(id, filter);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @put('/users/{id}', {
    responses: {
      '204': {
        description: 'User PUT success',
      },
    },
  })
  async replaceById(
    @param.path.number('id') id: number,
    @requestBody() user: User,
  ): Promise<void> {
    await this.userRepository.replaceById(id, user);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @del('/users/{id}', {
    responses: {
      '204': {
        description: 'User DELETE success',
      },
    },
  })
  async deleteById(@param.path.number('id') id: number): Promise<void> {
    await this.userRepository.deleteById(id);
  }

  @get('/users/me')
  @authenticate('jwt')
  async me(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<UserProfile> {
    // console.log(currentUser);
    currentUser.id = currentUser[securityId];
    return Promise.resolve(_.omit(currentUser, currentUser[securityId]));
  }




  @post('/users/become-a-labor')
  @authenticate('jwt')
  @authorize({
    allowedRoles: ['employer'],
    voters: [authorizeUser],
  })
  async becomeALabor(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Become a labor",
            properties: {
              skills: {
                type: 'array'
              }
            },
            required: ["skills"],
          },
        },
      },
    })
    requestData : {
      skills: Array<object>;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<User> {
    /**
     * todo add role as labor
     * add skills
     */
    const user = await this.userRepository.findById(currentUser.id)
    if(user.role.includes('labor')){
      throw new HttpErrors.BadRequest(`You're already a labor`)
    }
    user.role.push('labor')
    await this.userRepository.updateById(currentUser.id, user);

    const employerInfo = await this.employerRepository.findOne({where:{userId: currentUser.id}});

    await this.laborRepository.create({
      userId: currentUser.id,
      skills: requestData.skills,
      location: employerInfo.location,
      phone: employerInfo.phone
    })

    return user;
  }

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['employer', 'labor'],
    voters: [authorizeUser],
  })
    @get('/get-labor/{id}', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getLaborByID(
    @param.path.number('id') userId: number,
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<object> {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isDelete: false
      }
    })
    let profile = null
    profile = await this.laborRepository.findOne({
      where: {userId: user.id}
    })
    if(!profile){
      return {
        message: 'Labor not found'
      }
    }

    /**
     * adding profile viewed for labor
     */
    await this.viewerRepository.create({
      laborId: user.id,
      viewerId: currentUser.id
    })

    return {
      user,
      profile
    }
  }


    @get('/get-laborby-guest/{id}', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getLaborByIDforLabor(
    @param.path.number('id') userId: number,
    @param.query.object('viewer') viewer: object
  ): Promise<object> {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isDelete: false
      }
    })
    if(!user){
      return {
        message: 'Labor not found'
      }
    }
    let profile = null
    profile = await this.laborRepository.findOne({
      where: {userId: user.id}
    })
    if(!profile){
      return {
        message: 'Labor not found'
      }
    }

    /**
     * adding profile viewed for labor
     */
    await this.viewerRepository.create({
      laborId: user.id,
      viewerId: -1,
      viewerDetail: viewer
    })

    return {
      user,
      profile
    }
  }


/**
 * Todo:
 *  make relation between user table and viewer table
 *  pagination
 */

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor'],
    voters: [authorizeUser],
  })
    @get('/get-profile-views', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getProfileViews(
    @param.query.date('startDate') startDate: Date,
    @param.query.date('endDate') endDate: Date,
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<object> {
    let profile = null
    profile = await this.viewerRepository.find({
      where: {
        laborId: currentUser.id, 
        createdAt: {
          between: [startDate, endDate]
        }
      }
    })
    return {
      profile
    }
  }

  @post("/users/verify-otp-number")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["employer", "labor"],
    voters: [authorizeUser],
  })
  async verifyOTPForNumber(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              otp: {
                type: "string",
                maxLength: 6,
              },
            },
            required: ["otp"],
          },
        },
      },
    })
    requestData: {
      otp: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    console.log(requestData);
    const otp: any = await this.otpRepository.findOne({
      where: {
        otp: requestData.otp,
        type: "CHANGE_NUMBER",
        userId: currentUser.id,
      },
    });
    if (!otp) {
      throw new HttpErrors.NotFound(`user not found with this otp`);
    }
    const user = await this.userRepository.findById(otp?.userId);
    console.log(user);
    const t = await this.employerRepository.findOne({});
    console.log(t.userId);

    let employer = await this.employerRepository.findOne({
      where: { userId: user.id },
    });
    let labor = await this.laborRepository.findOne({
      where: { userId: user.id },
    });
    console.log(
      await this.laborRepository.findOne({
        where: { userId: user.id },
      })
    );
    console.log(
      await this.employerRepository.findOne({
        where: { userId: user.id },
      })
    );
    if (employer) {
      employer.phone = otp.data.number;
      console.log(otp.data.number);
      await this.employerRepository.updateById(employer.id, employer);
    }

    if (labor) {
      labor.phone = otp.data.number;
      console.log(otp.data.number);

      await this.laborRepository.updateById(labor.id, labor);
    }
    await this.otpRepository.deleteAll({
      userId: currentUser.id,
      type: "CHANGE_NUMBER",
    });
    return {
      message: "Your mobile number successfully changed!",
    };
  }

  @post("/users/update-number")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["employer", "labor"],
    voters: [authorizeUser],
  })
  async updatePhone(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              number: {
                type: "string",
              },
            },
            required: ["number"],
          },
        },
      },
    })
    requestData: {
      number: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findById(currentUser.id)

    const otp = generateOTP(currentUser.id);
    await this.otpRepository.deleteAll({
      userId: currentUser.id,
      type: "CHANGE_NUMBER",
    });
    await this.otpRepository.create({
      userId: currentUser.id,
      otp: otp,
      type: "CHANGE_NUMBER",	
      data: requestData,
    });
    await this.emailService.sendEmail(
      user.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for mobile number on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the mobile number change.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );
    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
    };
  }



  @post("/users/update-location")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor"],
    voters: [authorizeUser],
  })
  async updateLocation(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              lat: {
                type: "number",
              },
              lng: {
                type: "number",
              },
            },
            required: ["lat", "lng"],
          },
        },
      },
    })
    requestData: {
      lat: number;
      lng: number;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    await this.locationRepository.deleteAll({
      type: "LOCATION_CHANGE",
      userId: currentUser.id,
    });
    await this.locationRepository.create({
      type: "LOCATION_CHANGE",
      userId: currentUser.id,
      data: requestData,
    });
    return {
      message:
        "Request sent, Your new location will be updated after the admin verification",
    };
  }


  @get("/users/account-status")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  async viewAccountStatus(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string, data: object }> {
    const data = await this.userRepository.findById(currentUser.id, {});
    return {
      message:
        "Account status successfully fetched!",
        data: _.pick(data, ['active'])
    }
  }

  @get("/users/delete-account")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  async deleteAccount(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    const data = await this.userRepository.findById(currentUser.id, {});
    const otp = generateOTP(currentUser.id);
    console.log(currentUser.id)
    await this.otpRepository.deleteAll({
      userId: currentUser.id,
      type: "DELETE_ACCOUNT",
    });
    await this.otpRepository.create({
      userId: currentUser.id,
      otp: otp,
      type: "DELETE_ACCOUNT",	
      data: {isDelete: true},
    });
    await this.emailService.sendEmail(
      data.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for deleting your account on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the delete process.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );
    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
    };
  }


  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @post('/users/verify-delete-otp', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async verifyDeleteOTP(
    @requestBody({
      description: 'The Input otp verification',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['otp'],
            properties: {
              otp: {
                type: 'string',
                maxLength: 6,
              },
            },
          },
        },
      },
    })
    request: {
      otp: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{message: string}> {
    console.log(currentUser.id)
    const otp:any = await this.otpRepository.findOne({
      where: {
        otp: request.otp,
        userId: currentUser.id,
        type: "DELETE_ACCOUNT",
      },
    });
    if (!otp) {
      throw new HttpErrors.NotFound(`user not found with this otp`);
    }
    console.log(otp.data)
    await this.userRepository.updateById(otp?.userId, {isDelete: true});
    await this.otpRepository.deleteAll({userId: otp.userId, type: "DELETE_ACCOUNT"});
    await this.disconnectedRepository.create({
      userId: otp.userId,
    })
    return {
      message: 'Your account has been deleted!'
    };
  }



  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @get('/users/enable-disable-2fa', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                message: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async toggle2fa(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{message: string, status: boolean}> {
    console.log(currentUser.id)
    const user = await this.userRepository.findById(currentUser.id)
    user.tfa = !user.tfa
    await this.userRepository.update(user)
    return {
      message: '2FA has been updated',
      status: user.tfa
    };
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @post("/users/store-token", {
    responses: {
      "200": {
        description: "Token",
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                },
              },
            },
          },
        },
      },
    },
  })
  async storeToken(
    @requestBody({
      description: "The Input store token",
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            required: ["token"],
            properties: {
              token: {
                type: "string"
              },
            },
          },
        },
      },
    })
    request: {
      token: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    console.log(currentUser.id);
    
    await this.userRepository.updateById(currentUser.id, { messageToken: request.token });
    return {
      message: "Token has been stored!",
    };
  }

}

import {BindingScope, injectable} from '@loopback/core';
import nodemailer from 'nodemailer';

@injectable({scope: BindingScope.TRANSIENT})
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
        host: 'mail.smtp2go.com',
        port: 2525, // your SMTP port
        secure: false, // false for TLS; true for SSL
        auth: {
          user: 'marees',
          pass: 'c7XO5Sylg1EHuhwu',
        },
    });
  }

  async sendEmail(to: string, subject: string, text: string) {
    const mailOptions = {
      from: 'mareeskratos@gmail.com	',
      to,
      subject,
      html: text,
    };

    return this.transporter.sendMail(mailOptions);
  }
}
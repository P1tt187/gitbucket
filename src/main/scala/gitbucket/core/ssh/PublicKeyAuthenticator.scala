package gitbucket.core.ssh

import java.security.PublicKey

import gitbucket.core.service.SshKeyService
import gitbucket.core.servlet.Database
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.session.ServerSession

class PublicKeyAuthenticator extends PublickeyAuthenticator with SshKeyService {

  override def authenticate(username: String, key: PublicKey, session: ServerSession): Boolean = {
    Database() withSession { implicit dbSession =>
      if (!"git".equals(username)) {
        false
      } else {
        getAllKeys().filter(k=> k.publicKey!= null && !k.publicKey.trim.isEmpty).exists{
          sshKey =>
            SshUtil.str2PublicKey(sshKey.publicKey) match {
              case Some(pubKey) => key.equals(pubKey)
              case _=> false
            }
        }
      }
    }
  }

}

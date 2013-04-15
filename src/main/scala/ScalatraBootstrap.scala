import app._
import org.scalatra._
import javax.servlet._

class ScalatraBootstrap extends LifeCycle {
  override def init(context: ServletContext) {
    context.mount(new CreateRepositoryServlet, "/new")
    context.mount(new RepositoryViewerServlet, "/*")
    
    context.addListener(new ServletContextListener(){
      def contextInitialized(e: ServletContextEvent): Unit = {
        val dir = new java.io.File(_root_.util.Directory.GitBucketHome)
        if(!dir.exists){
          dir.mkdirs()
        }
      }
      
      def contextDestroyed(e: ServletContextEvent): Unit = {}
    })
  }
}
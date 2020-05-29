package burp;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    protected static ClassLoader loader;
    private static final String LIB_DIR = "./libs/";
    private static PrintStream _stdout;
    private static PrintStream _stderr;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // get our out/err streams
        BurpExtender._stderr = new PrintStream(callbacks.getStderr());
        BurpExtender._stdout = new PrintStream(callbacks.getStdout());
        
        // set our extension name
        callbacks.setExtensionName("BurpJDSer-ng by omerc.net");

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        callbacks.registerContextMenuFactory(this);
        
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of our custom editor tab
        return new SerializedJavaInputTab(controller, editable);
    }

    //
    // implement IContextMenuFactory
    //
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        Action reloadJarsAction = new ReloadJarsAction("BurpJDSer-ng: Reload JARs", invocation);
        JMenuItem reloadJars = new JMenuItem(reloadJarsAction);
        
        menu.add(reloadJars);
        return menu;
    }
    
    class ReloadJarsAction extends AbstractAction {

        IContextMenuInvocation invocation;
        
        public ReloadJarsAction(String text, IContextMenuInvocation invocation) {
            super(text);
            this.invocation = invocation;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
            _stdout.println("Reloading jars from " + LIB_DIR);
            refreshSharedClassLoader();
        }
        
    }

    //
    // class implementing IMessageEditorTab
    //
    class SerializedJavaInputTab implements IMessageEditorTab {

        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        private byte[] serializeMagic = new byte[]{-84, -19};
        private Object obj;
        private byte[] crap;
        private XStream xstream = new XStream(new DomDriver());

        public SerializedJavaInputTab(IMessageEditorController controller, boolean editable) {
            
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        
        
        //
        // implement IMessageEditorTab
        //act
        @Override
        public String getTabCaption() {
            return "Deserialized Java";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            // enable this tab for requests containing the serialized "magic" header
            return helpers.indexOf(content, serializeMagic, false, 0, content.length) > -1;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                CustomLoaderObjectInputStream is = null;
                try {

                    // save offsets
                    int magicPos = helpers.indexOf(content, serializeMagic, false, 0, content.length);
                    int msgBody = helpers.analyzeRequest(content).getBodyOffset();

                    // get serialized data
                    byte[] baSer = Arrays.copyOfRange(content, magicPos, content.length);

                    // save the crap buffer for reconstruction
                    crap = Arrays.copyOfRange(content, msgBody, magicPos);

                    // deserialize the object
                    ByteArrayInputStream bais = new ByteArrayInputStream(baSer);

                    // Use a custom OIS that uses our own ClassLoader
                    
                    is = new CustomLoaderObjectInputStream(bais, getSharedClassLoader());
                    obj = is.readObject();
                    String xml = xstream.toXML(obj);

                    txtInput.setText(xml.getBytes());
                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    txtInput.setText(helpers.stringToBytes("Something went wrong, did you change the body in a bad way?\n\n" + getStackTrace(ex)));
                } finally {
                    try {
                        is.close();
                    } catch (IOException ex) {
                        Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
                txtInput.setEditable(editable);
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified()) {
                // xstream doen't like newlines
                String xml = helpers.bytesToString(txtInput.getText()).replace("\n", "");
                // reserialize the data
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try {
                    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                        oos.writeObject(xstream.fromXML(xml));
                        oos.flush();
                    }
                } catch (IOException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                }
                // reconstruct our message (add the crap buffer)
                byte[] baObj = baos.toByteArray();
                byte[] newBody = new byte[baObj.length + crap.length];
                System.arraycopy(crap, 0, newBody, 0, crap.length);
                System.arraycopy(baObj, 0, newBody, crap.length, baObj.length);

                return helpers.buildHttpMessage(helpers.analyzeRequest(currentMessage).getHeaders(), newBody);
            } else {
                return currentMessage;
            }
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }

        private String getStackTrace(Throwable t) {
            StringWriter stringWritter = new StringWriter();
            PrintWriter printWritter = new PrintWriter(stringWritter, true);
            t.printStackTrace(printWritter);
            printWritter.flush();
            stringWritter.flush();

            return stringWritter.toString();
        }
    }
    
    protected static ClassLoader createURLClassLoader(String libDir) {
		File dependencyDirectory = new File(libDir);
		File[] files = dependencyDirectory.listFiles();
		ArrayList<URL> urls = new ArrayList<>();
	
		for (int i = 0; i < files.length; i++) {
			if (files[i].getName().endsWith(".jar")) {
				try {
					_stdout.println("Loading: " + files[i].getName());
					urls.add(files[i].toURI().toURL());
				} catch (MalformedURLException ex) {
					Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
					_stderr.println("!! Error loading: " + files[i].getName());
				}
			}
		}
	
		return new URLClassLoader(urls.toArray(new URL[urls.size()]));
	}
    
    public static ClassLoader getSharedClassLoader() {
        if(loader == null) {
                refreshSharedClassLoader();
        }
        return loader;
    }
    
    public static void refreshSharedClassLoader() {
        loader = createURLClassLoader(LIB_DIR);
    }
}
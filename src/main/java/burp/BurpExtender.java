package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
TODO:
    Class loading is done every time message tab is loaded and information about loaded JARs is in plugin stdout/err.
    A friendlier implementation would be have a UI element listing the loaded JARs with buttons to add/remove JARs
    similar to how BurpExtender plugins are loaded manually.
    Options:
        * Use ITab to implement a top level UI tab
        * Inside the Java Object window show the list so it's easier to manipulate the list as you're testing
*/

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintStream _stdout;
    private Utils utils;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.utils = new Utils(this.helpers, callbacks);
        this._stdout = new PrintStream(callbacks.getStdout());

        // set our extension name
        callbacks.setExtensionName("BurpJDSer-ng by omerc.net");

        // register ourselves as a message editor tab factory
        callbacks.registerContextMenuFactory(this);
        callbacks.registerMessageEditorTabFactory(this);

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
            _stdout.println("Reloading jars from " + utils.LIB_DIR);
            utils.refreshSharedClassLoader();
        }

    }

    //
    // class implementing IMessageEditorTab
    //
    class SerializedJavaInputTab implements IMessageEditorTab {

        private final boolean editable;
        private final ITextEditor txtInput;
        private byte[] currentMessage;
        private final byte[] serializeMagic = new byte[]{-84, -19};
        private byte[] crap;

        public SerializedJavaInputTab(IMessageEditorController controller, boolean editable) {

            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }


        //
        // implement IMessageEditorTab
        //
        @Override
        public String getTabCaption() {
            return "Java Object";
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
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                // save offsets
                int magicPos = helpers.indexOf(content, serializeMagic, false, 0, content.length);
                int messageBody = helpers.analyzeRequest(content).getBodyOffset();

                // get serialized data
                byte[] baSer = Arrays.copyOfRange(content, magicPos, content.length);

                // save the crap buffer for reconstruction
                crap = Arrays.copyOfRange(content, messageBody, magicPos);

                // deserialize the object
                txtInput.setText(utils.Deserialize(baSer));
                txtInput.setEditable(editable);
            }

            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the deserialized data
            if (txtInput.isTextModified()) {
                byte[] baObj = new byte[0];
                try {
                    baObj = utils.Serialize(txtInput.getText());
                } catch (Exception ex) {
                    if (ex instanceof com.thoughtworks.xstream.io.StreamException) callbacks.issueAlert(ex.getCause().getMessage());
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    return currentMessage;
                }

                // rebuild with crap buffer
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
    }
}
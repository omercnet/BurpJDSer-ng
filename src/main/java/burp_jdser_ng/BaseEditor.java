package burp_jdser_ng;

import java.awt.Component;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import burp.api.montoya.utilities.ByteUtils;

abstract class BaseEditor implements ExtensionProvidedEditor {

    protected final RawEditor editor;
    protected final JDSer jdSer;
    protected final ByteUtils byteUtils;
    protected HttpRequestResponse requestResponse;

    protected byte[] payload;

    BaseEditor(MontoyaApi api, EditorCreationContext creationContext, JDSer jdSer) {
        this.jdSer = jdSer;
        this.byteUtils = api.utilities().byteUtils();

        if (creationContext.editorMode() == EditorMode.READ_ONLY) {
            editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        } else {
            editor = api.userInterface().createRawEditor();
        }
    }

    @Override
    public String caption() {
        return "Java Object";
    }

    @Override
    public Component uiComponent() {
        return editor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return editor.selection().isPresent() ? editor.selection().get() : null;
    }

    @Override
    public boolean isModified() {
        return editor.isModified();
    }
}

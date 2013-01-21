/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

/**
 *
 * @author omercohen
 */
public class MyObjectInputStream extends ObjectInputStream 
{
    
    ClassLoader loader;
    
    public MyObjectInputStream(InputStream in, ClassLoader loader) throws IOException
    {
        super(in);
        this.loader = loader;
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException
    {
        return Class.forName(desc.getName(), false, loader);
    }
}
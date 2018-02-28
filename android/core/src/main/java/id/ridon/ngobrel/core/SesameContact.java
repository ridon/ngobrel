package id.ridon.ngobrel.core;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/**
 * This class represents a Sesame contact
 */
public class SesameContact {
  public String id;

  HashMap<HashId, SesameDevice> devices = new HashMap<>();
  ArrayList<HashId> activeSessions = new ArrayList<>();
  Date staleTime;

  public SesameContact(String id) {
    this.id = id;
    staleTime = new Date(0);
  }
}

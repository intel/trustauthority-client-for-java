/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.trustauthority.configfsi;

import java.nio.file.Paths;
import com.intel.trustauthority.exception.PathException;

public class TsmPath {
	
	
	public static final String SEPERATOR = "/";
	
	public String subsystem;
	public String entry;
	public String attribute;
	
	public TsmPath(String subsystem) {
		this.subsystem = subsystem;
	}
	
	public TsmPath(String subsystem, String entry) {
		this.subsystem = subsystem;
		this.entry = entry;
	}

	public TsmPath(String subsystem, String entry, String attribute) {
		this.subsystem = subsystem;
		this.entry = entry;
		this.attribute = attribute;
	}
	
	@Override
	public String toString(){
		if (this.attribute == null) {
			return Paths.get(Constants.TSM_PREFIX, this.subsystem, this.entry).toString();
		}else {
			return Paths.get(Constants.TSM_PREFIX, this.subsystem, this.entry, this.attribute).toString();
		}
	}
	
	public TsmPath clone() {
		return new TsmPath(this.subsystem, this.entry, this.attribute);
		
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!TsmPath.class.isInstance(obj)) {
			return false;
		}
		
		TsmPath tsmPath = (TsmPath)obj; 
		return (tsmPath.subsystem == this.subsystem || (tsmPath.subsystem != null && tsmPath.subsystem.equals(this.subsystem))) && 
				(tsmPath.entry == this.entry || (tsmPath.entry != null && tsmPath.entry.equals(this.entry))) && 
				(tsmPath.attribute == this.attribute || (tsmPath.attribute != null && tsmPath.attribute.equals(this.attribute)));
	}
	
	/* Getters and setters*/
	public String getSubsystem() {
		return subsystem;
	}

	public void setSubsystem(String subsystem) {
		this.subsystem = subsystem;
	}

	public String getEntry() {
		return entry;
	}

	public void setEntry(String entry) {
		this.entry = entry;
	}

	public String getAttribute() {
		return attribute;
	}

	public void setAttribute(String attribute) {
		this.attribute = attribute;
	}

	
	
	public static TsmPath ParseTsmPath(String path) throws PathException {
		if(!path.startsWith(Constants.TSM_PREFIX)) {
			throw new PathException(String.format("%s does not begin with %s", path, Constants.TSM_PREFIX));
		} 
		//check if mentioned path has sub-system or not.  
		// this code is applicable only for linux hence using "/"
		String subSystemPath = path.trim().replace(Constants.TSM_PREFIX, "").replaceFirst(SEPERATOR, "").trim();
		if(subSystemPath == "") {
			throw new PathException(String.format("%s does not contain a subsystem", path));
		}		
		
		String[] subSystems = subSystemPath.split(SEPERATOR);
		if (subSystems.length == 1){
			return new TsmPath(subSystems[0]);			
		}
		if (subSystems.length == 2){
			return new TsmPath(subSystems[0],subSystems[1]);			
		}
		if (subSystems.length == 3){
			return new TsmPath(subSystems[0],subSystems[1],subSystems[2]);			
		}
		throw new PathException(String.format("%s suffix expected to be of form subsystem[/entry[/attribute]] (debug %s)", path, subSystemPath));		
	}
		
}

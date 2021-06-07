package main

import (
	"github.com/robertkrimen/otto"
	"io/ioutil"
	"log"
)


var Vm *otto.Otto
func CreatVM(){
	bytes,err := ioutil.ReadFile("./main/all.min.js")
	if err != nil {
		log.Printf("read js failed with err : %v",err)
		panic("")
	}else{
		Vm = otto.New()
		_,err= Vm.Run(string(bytes))
		if err != nil {
			panic(err)
		}

	}



}
